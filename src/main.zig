const std = @import("std");
const posix = std.posix;

const Certificate = @import("Certificate.zig");
const tls = @import("tls.zig");

var server_host: []const u8 = undefined;
var tls_name: []const u8 = undefined;
const server_port = 443;
var path: []const u8 = undefined;
const remote_host = "127.0.0.1";
const remote_port = "51820";
/// porta local (o endpoint do peer no wg); pode mudar pelo 1o argumento
const default_listen_port = 51820;

/// data minima plausivel (2026-01-01): antes disso o relogio nao foi acertado
const clock_floor = 1767225600;
/// sem nada do servidor por esse tempo, a conexao e dada como morta
const dead_after_s = 90;
const ping_every_s = 25;


pub const panic = std.debug.no_panic;

fn say(parts: []const []const u8) void {
    for (parts) |p| _ = posix.write(2, p) catch {};
    _ = posix.write(2, "\n") catch {};
}

pub fn main() void {
    const gpa = std.heap.page_allocator;
    var args = std.process.args();
    _ = args.skip();
    const port_arg = args.next() orelse { say(&.{"usage: wsudp PORT SERVER TLS_NAME PATH CA_DER"}); return; };
    const port = std.fmt.parseInt(u16, port_arg, 10) catch return;
    server_host = args.next() orelse return;
    tls_name = args.next() orelse return;
    path = args.next() orelse return;
    const ca_file = args.next() orelse return;
    if (args.next() != null or path.len == 0 or path[0] != '/') return;
    const der_file = std.fs.cwd().readFileAlloc(gpa, ca_file, 65536) catch { say(&.{"wsudp: cannot read CA DER"}); return; };
    const roots = [_][]const u8{der_file};


    while (std.time.timestamp() < clock_floor) {
        say(&.{"wsudp: esperando o relogio (NTP)"});
        std.time.sleep(5 * std.time.ns_per_s);
    }

    var bundle: Certificate.Bundle = .{};
    const now = std.time.timestamp();
    for (roots) |der| {
        const start: u32 = @intCast(bundle.bytes.items.len);
        bundle.bytes.appendSlice(gpa, der) catch return;
        bundle.parseCert(gpa, start, now) catch {
            say(&.{"wsudp: raiz embutida invalida"});
            return;
        };
    }

    const udp = openUdp(port) catch |err| {
        say(&.{ "wsudp: udp local: ", @errorName(err) });
        return;
    };
    say(&.{ "wsudp: udp local -> wss://", server_host, path });

    var backoff: u64 = 2;
    while (true) {
        if (session(gpa, bundle, udp)) |_| {
            backoff = 2;
        } else |err| {
            say(&.{ "wsudp: sessao caiu: ", @errorName(err) });
        }
        std.time.sleep(backoff * std.time.ns_per_s);
        backoff = @min(backoff * 2, 60);
    }
}

fn openUdp(port: u16) !posix.socket_t {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    const a = try std.net.Address.parseIp4("127.0.0.1", port);
    try posix.bind(fd, &a.any, a.getOsSockLen());
    return fd;
}

const Conn = struct {
    stream: std.net.Stream,
    tls: tls.Client,

    fn write(c: *Conn, bytes: []const u8) !void {
        try c.tls.writeAll(c.stream, bytes);
    }
};

fn session(gpa: std.mem.Allocator, bundle: Certificate.Bundle, udp: posix.socket_t) !void {
    const stream = try std.net.tcpConnectToHost(gpa, server_host, server_port);
    defer stream.close();

    var c: Conn = .{
        .stream = stream,
        .tls = try tls.Client.init(stream, .{
            .host = .{ .explicit = tls_name },
            .ca = .{ .bundle = bundle },
        }),
    };

    // ---- upgrade HTTP -> WebSocket, com o destino no JWT (protocolo do wstunnel)
    var key_raw: [16]u8 = undefined;
    std.crypto.random.bytes(&key_raw);
    var key: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key, &key_raw);

    var jwt_buf: [512]u8 = undefined;
    const jwt = makeJwt(&jwt_buf);

    var req_buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&req_buf);
    const w = fbs.writer();
    try w.print("GET {s} HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ", .{ path, tls_name });
    try w.writeAll(&key);
    try w.writeAll("\r\nSec-WebSocket-Protocol: v1, authorization.bearer.");
    try w.writeAll(jwt);
    try w.writeAll("\r\n\r\n");
    try c.write(fbs.getWritten());

    // resposta: precisa ser 101; o que vier depois do cabecalho ja e WebSocket
    var rx: [65536 + 16]u8 = undefined;
    var rx_len: usize = 0;
    const hdr_end = while (true) {
        if (rx_len == rx.len) return error.RespostaGrandeDemais;
        const n = try c.tls.read(stream, rx[rx_len..]);
        if (n == 0) return error.FechouNoUpgrade;
        rx_len += n;
        if (std.mem.indexOf(u8, rx[0..rx_len], "\r\n\r\n")) |i| break i + 4;
    };
    if (!std.mem.startsWith(u8, rx[0..rx_len], "HTTP/1.1 101")) {
        const line_end = std.mem.indexOf(u8, rx[0..rx_len], "\r\n") orelse rx_len;
        say(&.{ "wsudp: upgrade recusado: ", rx[0..line_end] });
        return error.UpgradeRecusado;
    }
    std.mem.copyForwards(u8, &rx, rx[hdr_end..rx_len]);
    rx_len -= hdr_end;
    say(&.{"wsudp: tunel aberto"});

    // ---- duas threads: esta le o UDP do wg e escreve no TLS; a outra le o
    // TLS e entrega no UDP. Ler/escrever no cliente TLS ao mesmo tempo e ok
    // (estados separados); escritas sao serializadas pelo mutex.
    var sh: Shared = .{ .c = &c, .udp = udp, .last_rx = std.atomic.Value(u32).init(now32()) };
    @memcpy(sh.rx[0..rx_len], rx[0..rx_len]);
    sh.rx_len = rx_len;
    const reader = try std.Thread.spawn(.{}, readLoop, .{&sh});
    defer {
        // derruba o socket para o leitor sair do read bloqueante
        posix.shutdown(stream.handle, .both) catch {};
        reader.join();
    }

    var dgram: [65536]u8 = undefined;
    var frame_out: [65536 + 14]u8 = undefined;
    var last_tx = std.time.timestamp();
    while (!sh.dead.load(.acquire)) {
        var fds = [_]posix.pollfd{.{ .fd = udp, .events = posix.POLL.IN, .revents = 0 }};
        _ = try posix.poll(&fds, 5000);
        if (fds[0].revents & posix.POLL.IN != 0) {
            var from: posix.sockaddr.in = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = posix.recvfrom(udp, &dgram, 0, @ptrCast(&from), &from_len) catch 0;
            if (n > 0) {
                sh.peer_mu.lock();
                sh.peer = from;
                sh.have_peer = true;
                sh.peer_mu.unlock();
                try sh.send(encodeFrame(&frame_out, 0x2, dgram[0..n]));
                last_tx = std.time.timestamp();
            }
        }
        const t = std.time.timestamp();
        if (now32() -% sh.last_rx.load(.acquire) > dead_after_s) return error.SemRespostaDoServidor;
        if (t - last_tx > ping_every_s) {
            try sh.send(encodeFrame(&frame_out, 0x9, ""));
            last_tx = t;
        }
    }
    return error.ServidorFechou;
}

fn now32() u32 {
    return @truncate(@as(u64, @intCast(std.time.timestamp())));
}

const Shared = struct {
    c: *Conn,
    udp: posix.socket_t,
    write_mu: std.Thread.Mutex = .{},
    peer_mu: std.Thread.Mutex = .{},
    peer: posix.sockaddr.in = undefined,
    have_peer: bool = false,
    /// segundos (32 bits: MIPS32 nao tem atomico de 64)
    last_rx: std.atomic.Value(u32),
    dead: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    rx: [65536 + 16]u8 = undefined,
    rx_len: usize = 0,

    fn send(sh: *Shared, bytes: []const u8) !void {
        sh.write_mu.lock();
        defer sh.write_mu.unlock();
        try sh.c.write(bytes);
    }
};

fn readLoop(sh: *Shared) void {
    defer sh.dead.store(true, .release);
    var pong: [256]u8 = undefined;
    while (true) {
        while (nextFrame(&sh.rx, &sh.rx_len) catch return) |f| {
            sh.last_rx.store(now32(), .release);
            switch (f.opcode) {
                0x2 => {
                    sh.peer_mu.lock();
                    const have = sh.have_peer;
                    const peer = sh.peer;
                    sh.peer_mu.unlock();
                    if (have) _ = posix.sendto(sh.udp, f.payload, 0, @ptrCast(&peer), @sizeOf(posix.sockaddr.in)) catch {};
                },
                0x9 => if (f.payload.len <= pong.len - 14) {
                    sh.send(encodeFrame(&pong, 0xA, f.payload)) catch return;
                },
                0x8 => return,
                else => {},
            }
            f.consume(&sh.rx, &sh.rx_len);
        }
        if (sh.rx_len == sh.rx.len) return;
        const n = sh.c.tls.read(sh.c.stream, sh.rx[sh.rx_len..]) catch return;
        if (n == 0) return;
        sh.rx_len += n;
        sh.last_rx.store(now32(), .release);
    }
}

const Frame = struct {
    opcode: u8,
    payload: []const u8,
    total: usize,

    fn consume(f: Frame, rx: []u8, rx_len: *usize) void {
        std.mem.copyForwards(u8, rx, rx[f.total..rx_len.*]);
        rx_len.* -= f.total;
    }
};

/// quadro do servidor (sem mascara); null se ainda nao chegou inteiro
fn nextFrame(rx: []u8, rx_len: *usize) !?Frame {
    const b = rx[0..rx_len.*];
    if (b.len < 2) return null;
    const opcode = b[0] & 0x0f;
    if (b[1] & 0x80 != 0) return error.QuadroMascaradoDoServidor;
    var len: u64 = b[1] & 0x7f;
    var off: usize = 2;
    if (len == 126) {
        if (b.len < 4) return null;
        len = std.mem.readInt(u16, b[2..4], .big);
        off = 4;
    } else if (len == 127) {
        if (b.len < 10) return null;
        len = std.mem.readInt(u64, b[2..10], .big);
        off = 10;
    }
    if (len > rx.len - off) return error.QuadroGrandeDemais;
    const total = off + @as(usize, @intCast(len));
    if (b.len < total) return null;
    return .{ .opcode = opcode, .payload = b[off..total], .total = total };
}

/// quadro do cliente: FIN + bit de mascara (chave zero, ver abaixo)
fn encodeFrame(out: []u8, opcode: u8, payload: []const u8) []const u8 {
    out[0] = 0x80 | opcode;
    var off: usize = 2;
    if (payload.len < 126) {
        out[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= 0xffff) {
        out[1] = 0x80 | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload.len), .big);
        off = 4;
    } else {
        out[1] = 0x80 | 127;
        std.mem.writeInt(u64, out[2..10], payload.len, .big);
        off = 10;
    }
    // mascara zerada: o RFC exige o bit de mascara do cliente, mas o servidor
    // do wstunnel (websocket_mask_frame=false, o padrao) nao desmascara. Com
    // chave zero o conteudo e o mesmo nos dois casos. Dentro do TLS a mascara
    // nao tem papel de seguranca (ela protege caches de proxies em texto claro).
    @memset(out[off..][0..4], 0);
    off += 4;
    @memcpy(out[off..][0..payload.len], payload);
    return out[0 .. off + payload.len];
}

/// JWT HS256 com o destino do tunel. O wstunnel le sem verificar a assinatura
/// (quem restringe e o --restrict-to do servidor), mas mandamos um JWT valido.
fn makeJwt(out: []u8) []const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const header = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

    var id_raw: [16]u8 = undefined;
    std.crypto.random.bytes(&id_raw);
    id_raw[6] = (id_raw[6] & 0x0f) | 0x40;
    id_raw[8] = (id_raw[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(id_raw, .lower);
    var uuid: [36]u8 = undefined;
    @memcpy(uuid[0..8], hex[0..8]);
    uuid[8] = '-';
    @memcpy(uuid[9..13], hex[8..12]);
    uuid[13] = '-';
    @memcpy(uuid[14..18], hex[12..16]);
    uuid[18] = '-';
    @memcpy(uuid[19..23], hex[16..20]);
    uuid[23] = '-';
    @memcpy(uuid[24..36], hex[20..32]);

    var claims_buf: [192]u8 = undefined;
    var cl = std.io.fixedBufferStream(&claims_buf);
    cl.writer().writeAll("{\"id\":\"") catch unreachable;
    cl.writer().writeAll(&uuid) catch unreachable;
    cl.writer().writeAll("\",\"p\":{\"Udp\":{\"timeout\":null}},\"r\":\"" ++ remote_host ++
        "\",\"rp\":" ++ remote_port ++ "}") catch unreachable;
    const cj = cl.getWritten();

    var o: usize = 0;
    o += enc.encode(out[o..], header).len;
    out[o] = '.';
    o += 1;
    o += enc.encode(out[o..], cj).len;
    const signed = out[0..o];

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signed, &key);
    out[o] = '.';
    o += 1;
    o += enc.encode(out[o..], &mac).len;
    return out[0..o];
}
