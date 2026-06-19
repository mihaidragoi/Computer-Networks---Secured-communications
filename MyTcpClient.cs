using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ComunicatiiSecurizate
{
    public class MyTcpClient
    {
        public void Connect()
        {
            System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("127.0.0.1", 8080);
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Conectat la server!");

            DiffieHellman dh = new DiffieHellman(23, 5);

            byte[] buffer = new byte[4096];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            SecurePacket? handshakeIn = new SecurePacket().Deserializer(buffer.Take(bytesRead).ToArray());

            if (handshakeIn != null && handshakeIn.Type == "HANDSHAKE")
            {
                int serverPubKey = BitConverter.ToInt32(handshakeIn.Payload);
                dh.CalculateSharedSecret(serverPubKey);
                Console.WriteLine($"[DH] Am primit cheia serverului: {serverPubKey}");
                Console.WriteLine($"[DH] Secret Comun stabilit: {dh.SharedSecret}");

                SecurePacket handshakeOut = new SecurePacket
                {
                    Type = "HANDSHAKE",
                    Payload = BitConverter.GetBytes(dh.PublicKey)
                };
                byte[] outData = handshakeOut.Serializer();
                stream.Write(outData, 0, outData.Length);
            }

            CryptService crypto = new CryptService();
            byte[] key = crypto.DerivedKey(dh.SharedSecret);


            Task.Run(() =>
            {
                byte[] readBuffer = new byte[4096];
                while (true)
                {
                    try
                    {
                        int readBytes = stream.Read(readBuffer, 0, readBuffer.Length);
                        if (readBytes == 0) break;

                        SecurePacket? receivedPackage = new SecurePacket().Deserializer(readBuffer.Take(readBytes).ToArray());

                        if (receivedPackage != null && receivedPackage.Type == "CHAT")
                        {
                            byte[] computedHash = crypto.ComputeHash(receivedPackage.Payload);

                            if (!computedHash.SequenceEqual(receivedPackage.Hash))
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("\n[EROARE]: Integritatea pachetului compromisă! Mesaj respins.");
                                Console.ResetColor();
                                continue;
                            }

                            string decryptedText = crypto.Decrypt(receivedPackage.Payload, key, receivedPackage.IV);

                            Console.WriteLine($"\n\n[Message] From: {receivedPackage.SenderName}");
                            Console.WriteLine($"[Primit Criptat]: {BitConverter.ToString(receivedPackage.Payload).Replace("-", "")}");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.WriteLine($"[Primit Decriptat]: {decryptedText}");
                            Console.ResetColor();
                            Console.Write("Introdu mesaj: "); 
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"\nConexiune închisă sau eroare: {ex.Message}");
                        break;
                    }
                }
            });


            while (true)
            {
                Console.Write("Introdu mesaj: ");
                string? text = Console.ReadLine();
                if (string.IsNullOrEmpty(text)) break;

                var encryptionResult = crypto.Encrypt(text, key);
                byte[] hash = crypto.ComputeHash(encryptionResult.Ciphertext);

                SecurePacket chatPacket = new SecurePacket
                {
                    Type = "CHAT",
                    Payload = encryptionResult.Ciphertext,
                    IV = encryptionResult.IV,
                    Hash = hash,
                    SenderName = "Client_User"
                };

                byte[] packetData = chatPacket.Serializer();
                stream.Write(packetData, 0, packetData.Length);

                Console.WriteLine($"[Trimis Criptat]: {BitConverter.ToString(chatPacket.Payload).Replace("-", "")}");
            }
        }
    }
}