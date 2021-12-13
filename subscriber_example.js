const buffer_size = 1024*1024;
const sock_path = "/var/run/xrpl-uplink/subscriber.sock";

const seq = require('unix-seqpacket');
const fs = require('fs');

let sub_fd = seq.open(sock_path);
let buf = Buffer.alloc(buffer_size)

const Int = (b, start, end) =>
{
    let s = '';
    for (let i = start; i < end; ++i)
        s = b.slice(i, i+1).toString('hex') + s;
    
    return parseInt(s, 16);
}

const Hex = (b, start, end) =>
{
    return b.slice(start, end).toString('hex')
}

const IP = (b, start, end) =>
{
    let s = Hex(b, start, end);
    if (s.substr(0, 24) == '00000000000000000000ffff')
    {
        let ip = '';
        for (let i = 0; i < 4; ++i)
        {
            ip += parseInt(s.substr(i * 2 + 24, 2), 16);
            if (i != 3) ip += '.';
        }
        return ip;
    }
    return s;
}
while(true)
{
    let bytes_read = fs.readSync(sub_fd, buf);

    console.log("bytes_read:", bytes_read)
   
    let flags =         Int(buf,   0,  4);

    if ((flags >> 28) == 0)
    {
        let header = {
            flags         : Int(buf,   0,   4),
            size          : Int(buf,   4,   8),
            timestamp     : Int(buf,   8,  12),
            type          : Int(buf,  12,  14),
            port          : Int(buf,  14,  16),
            addr          :  IP(buf,  16,  32),
            hash          : Hex(buf,  32,  64),
            source_peer   : Hex(buf,  64,  96),
            dest_peer     : Hex(buf,  96, 128)
        };

        let payload =       buf.slice(128, bytes_read);
   
        console.log(header);

    }
}

