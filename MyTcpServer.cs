using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ComunicatiiSecurizate
{
    public class MyTcpServer
    {
        public TcpListener tcpListener = new TcpListener(IPAddress.Parse("127.0.0.1"), 8080);

        public void Start()
        {
            tcpListener.Start();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Waiting for a client connection...");
            Console.ResetColor();
        }

        public void HandleClient()
        {
            System.Net.Sockets.TcpClient client = tcpListener.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Client connected successfully!");
            Console.ResetColor();

            DiffieHellman diffHellman = new DiffieHellman(23, 5);

            SecurePacket handshake = new SecurePacket { Type = "HANDSHAKE", Payload = BitConverter.GetBytes(diffHellman.PublicKey) };
            byte[] dataToSend = handshake.Serializer();
            stream.Write(dataToSend, 0, dataToSend.Length);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Send public key : {diffHellman.PublicKey}");
            Console.ResetColor();

            byte[] buffer = new byte[4096];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);

            SecurePacket? receivedHandshake = new SecurePacket().Deserializer(buffer.Take(bytesRead).ToArray());

            if (receivedHandshake != null && receivedHandshake.Type == "HANDSHAKE")
            {
                int clientPublicKey = BitConverter.ToInt32(receivedHandshake.Payload);
                diffHellman.CalculateSharedSecret(clientPublicKey);

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[DH] Key client primita: {clientPublicKey}");
                Console.WriteLine($"[DH] Shared secret calculat: {diffHellman.SharedSecret}");
                Console.ResetColor();

                CryptService crypto = new CryptService();
                byte[] key = crypto.DerivedKey(diffHellman.SharedSecret);

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
                        SenderName = "Server_User"
                    };

                    byte[] packetData = chatPacket.Serializer();
                    stream.Write(packetData, 0, packetData.Length);

                    Console.WriteLine($"[Trimis Criptat]: {BitConverter.ToString(chatPacket.Payload).Replace("-", "")}");
                }
            }
        }
    }
}