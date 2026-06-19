using ComunicatiiSecurizate;

public class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Alege modul: 1. Server | 2. Client");
        string choice = Console.ReadLine();

        if (choice == "1")
        {
            MyTcpServer server = new MyTcpServer();
            server.Start();
            server.HandleClient(); 
        }
        else if (choice == "2")
        {
            MyTcpClient client = new MyTcpClient();
            client.Connect();
        }
    }
}