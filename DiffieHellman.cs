using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace ComunicatiiSecurizate
{
    public class DiffieHellman
    {
        public int PrimNumber { get; set; }
        public int PrimitiveRoot {  get; set; }
        private int SecretKey { get; set; }
        public int SharedSecret {  get; set; }
        public int PublicKey { get; set; }

        public DiffieHellman(int p, int g)
        {
            PrimitiveRoot = g;
            PrimNumber = p;

            Random random = new Random();
            SecretKey = random.Next(2, PrimNumber-1);

            PublicKey = (int)BigInteger.ModPow(PrimitiveRoot, SecretKey, PrimNumber);
        }

        public void CalculateSharedSecret(int otherPublicKey)
        {
            SharedSecret = (int)BigInteger.ModPow(otherPublicKey, SecretKey, PrimNumber);
        }

    }
}
