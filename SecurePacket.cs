using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;


namespace ComunicatiiSecurizate
{
    public class SecurePacket
    {
        public byte[]? Payload {  get; set; }
        public byte[]? IV { get; set; }
        public byte[]? Hash { get; set; }
        public string? SenderName { get; set; }
        public string? Type { get; set; }

        public byte[] Serializer()
        {
            return JsonSerializer.SerializeToUtf8Bytes(this);
        }

        public SecurePacket? Deserializer(byte[] data)
        {
            return JsonSerializer.Deserialize<SecurePacket>(data);
        }
    }
}
