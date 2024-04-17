using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;



using SHA256 alg = SHA256.Create();
byte[] data = [];
byte[] hash = alg.ComputeHash(data);
byte[] signedHash = [];
RSAParameters sharedParameters = new RSAParameters();
var tcpListener = new TcpListener(IPAddress.Any, 8888);

try
{
    tcpListener.Start();    // запускаем сервер
    Console.WriteLine("Сервер запущен. Ожидание подключений... ");

    while (true)
    {
        // получаем подключение в виде TcpClient
        using var tcpClient = await tcpListener.AcceptTcpClientAsync();
        // получаем объект NetworkStream для взаимодействия с клиентом
        var stream = tcpClient.GetStream();
        // буфер для входящих данных
        var response = new List<byte>();
        int bytesRead = 1;
        var responseData = new List<string>();
        while (true)
        {
            // считываем данные до конечного символа
            while ((bytesRead = stream.ReadByte()) != '\n')
            {
                // добавляем в буфер
                response.Add((byte)bytesRead);
            }
            
            var resp = Encoding.UTF8.GetString(response.ToArray());
            response.Clear();
            responseData.Add(resp);
            
            if (resp == "END")
            {
                if (responseData[0] == "1")
                {
                    hash = Convert.FromBase64String(responseData[1]);
                    signedHash = Convert.FromBase64String(responseData[2]);
                    RSAParameters sharedParameters1 = new RSAParameters();

                    using (RSA rsa = RSA.Create())
                    {
                        sharedParameters1 = rsa.ExportParameters(false);
                    }
                        sharedParameters1.Modulus = Convert.FromBase64String(responseData[3]);
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(VerifySig(sharedParameters1,hash,signedHash)+'\n'));
                    response.Clear();
                    responseData.Clear();
                } else if (responseData[0] == "2")
                {
                    GetPublicKeyServer();
                     stream.Write(sharedParameters.Modulus);
                     stream.Write("\n"u8);
                    responseData.Clear();
                    
                }else if (responseData[0] == "3")
                {
                    hash = AutoGenerateMessageServer();
                    GenerateSig();


                    var encryptData = new string[] { Convert.ToBase64String(hash), Convert.ToBase64String(signedHash), Convert.ToBase64String(sharedParameters.Modulus) };
                    foreach (var word in encryptData)
                    {
                        // считыванием строку в массив байт
                        // при отправке добавляем маркер завершения сообщения - \n
                        byte[] EncData = Encoding.UTF8.GetBytes(word + '\n');
                        // отправляем данные
                         stream.Write(EncData);


                    }
                    stream.Write(Encoding.UTF8.GetBytes("END\n"));

                    while ((bytesRead = stream.ReadByte()) != '\n')
                    {
                        // добавляем в буфер
                        response.Add((byte)bytesRead);
                    }
                    var answer = Encoding.UTF8.GetString(response.ToArray());
                    Console.WriteLine($"{answer}");
                    response.Clear();
                    responseData.Clear();

                }
            }

        }
    }
}
finally
{
    tcpListener.Stop();
}

byte[] AutoGenerateMessageServer()
{
    data = Convert.FromBase64String($"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}" + $"{new Random().Next(0, 10)}");
    return alg.ComputeHash(data);


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
    }


}
void GenerateSigMod(byte[] modulus)
{
    using (RSA rsa = RSA.Create())
    {
        sharedParameters = rsa.ExportParameters(false);
        sharedParameters.Modulus = modulus;

        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
        rsaFormatter.SetHashAlgorithm(nameof(SHA256));

        signedHash = rsaFormatter.CreateSignature(hash);
    }
}
// Verify signature
string VerifySig(RSAParameters sharedParameters, byte[] hash, byte[] signedHash)
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
            return "The signature is valid.";
        }
        else
        {
            return "The signature is not valid.";
        }
    }

}

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