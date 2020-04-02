using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IO;
using System.Security.Cryptography;

namespace Skoruba.IdentityServer4.STS.Identity.Helpers
{
    public class RSAKeyUtils
    {
        private const string KEY_FILE = "./key.json";

        public static RsaSecurityKey GetKey()
        {
            RSAParameters keyParam;

            if (File.Exists(KEY_FILE))
                keyParam = GetKeyParameters(KEY_FILE);
            else
                keyParam = GenerateKeyAndSave(KEY_FILE);

            return new RsaSecurityKey(keyParam);
        }

        private static RSAParameters GetRSAKey()
        {
            RSAParameters keyParams;

            using (var rsaSvc = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    keyParams = rsaSvc.ExportParameters(true);
                }
                finally
                {
                    rsaSvc.PersistKeyInCsp = false;
                }
            }

            return keyParams;
        }

        private static RSAParameters GenerateKeyAndSave(string file)
        {
            var p = GetRSAKey();
            var t = new RSAParametersWithPrivate(p);

            File.WriteAllText(file, JsonConvert.SerializeObject(t));

            return p;
        }

        /// <summary>
        /// This expects a file in the format:
        /// {
        ///  "Modulus": "z7eXmrs9z3..xfQlw==",
        ///  "Exponent": "AQAB",
        ///  "P": "+VsET.....gADMM=",
        ///  "Q": "1U.....kP50=",
        ///  "DP": "CB.....6pFJiU=",
        ///  "DQ": "ND.....WhVUgCE=",
        ///  "InverseQ": "Heo.....0cU=",
        ///  "D": "Iv.....Smzxz/VsQ=="
        /// }
        ///
        /// Generate
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        private static RSAParameters GetKeyParameters(string file)
        {
            if (!File.Exists(file))
                throw new FileNotFoundException("RSA key file not available");

            var keyParams = JsonConvert.DeserializeObject<RSAParametersWithPrivate>(File.ReadAllText(file));
            return keyParams.ToRSAParameters();
        }

        /// <summary>
        /// Util class to allow restoring RSA parameters from JSON as the normal
        /// RSA parameters class won't restore private key info.
        /// </summary>
        private class RSAParametersWithPrivate
        {
            public byte[] D { get; set; }
            public byte[] DP { get; set; }
            public byte[] DQ { get; set; }
            public byte[] Exponent { get; set; }
            public byte[] InverseQ { get; set; }
            public byte[] Modulus { get; set; }
            public byte[] P { get; set; }
            public byte[] Q { get; set; }

            public RSAParametersWithPrivate()
            {
            }

            public RSAParametersWithPrivate(RSAParameters p)
            {
                D = p.D;
                DP = p.DP;
                DQ = p.DQ;
                Exponent = p.Exponent;
                InverseQ = p.InverseQ;
                Modulus = p.Modulus;
                P = p.P;
                Q = p.Q;
            }

            public RSAParameters ToRSAParameters()
            {
                return new RSAParameters()
                {
                    D = D,
                    DP = DP,
                    DQ = DQ,
                    Exponent = Exponent,
                    InverseQ = InverseQ,
                    Modulus = Modulus,
                    P = P,
                    Q = Q
                };
            }
        }
    }
}