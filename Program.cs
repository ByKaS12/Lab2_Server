using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

using SHA256 alg = SHA256.Create();
string data_str = Console.ReadLine();
byte[] data = Encoding.ASCII.GetBytes(data_str);
byte[] hash = alg.ComputeHash(data);
byte[] signedHash;
RSAParameters sharedParameters;
// Generate signature
void GenerateSig()
{
    using (RSA rsa = RSA.Create())
    {
        sharedParameters = rsa.ExportParameters(false);

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(nameof(SHA256));

        signedHash = rsaFormatter.CreateSignature(hash);
    }
}

// Verify signature
void VerifySig(RSAParameters sharedParameters, byte[] hash, byte[] signedHash)
{
    using (RSA rsa = RSA.Create())
    {
        rsa.ImportParameters(sharedParameters);

        RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
        rsaDeformatter.SetHashAlgorithm(nameof(SHA256));
        //byte[] hash1 = hash;
        //hash1[0] = 2;
        if (rsaDeformatter.VerifySignature(hash, signedHash))
        {
            Console.WriteLine("The signature is valid.");
        }
        else
        {
            Console.WriteLine("The signature is not valid.");
        }
    }

}
void menu()
{
    GenerateSig();
    VerifySig(sharedParameters, hash, signedHash);
}
void menu2()
{
    GetPublicKeyServer();
    Console.ReadKey();
    StreamReader reader = new StreamReader($"{Environment.CurrentDirectory}" + "//test.txt");
    sharedParameters.Modulus = Convert.FromBase64String(reader.ReadToEnd());
    reader.Close();
    VerifySig(sharedParameters, hash, signedHash);
}

void AutoGenerateMessageServer()
{
    data = Convert.FromBase64String($"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}");
    hash = alg.ComputeHash(data);


}

void GetPublicKeyServer()
{
    using (RSA rsa = RSA.Create())
    {
        sharedParameters = rsa.ExportParameters(false);

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(nameof(SHA256));
        AutoGenerateMessageServer();
        signedHash = rsaFormatter.CreateSignature(hash);
        StreamWriter writer = new StreamWriter($"{Environment.CurrentDirectory}" + "//test.txt");
        writer.WriteLine(Convert.ToBase64String(sharedParameters.Modulus));
        writer.Close();
    }


}
menu();
menu2();

