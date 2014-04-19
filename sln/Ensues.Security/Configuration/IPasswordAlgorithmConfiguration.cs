using System;

using Ensues.Security.Cryptography;
namespace Ensues.Configuration {
    
    internal interface IPasswordAlgorithmConfiguration {
        
        bool CompareInConstantTime { get; }

        HashFunction HashFunction { get; }

        Int16 SaltLength { get; }

        Int32 HashIterations { get; }
    }
}
