using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Ensues.Configuration;
namespace Ensues.Security.Cryptography {

    /// <summary>
    /// A class that can create a computation for a plain-text password
    /// that includes a cryptographic hash of that password and other
    /// information required to create that hash.
    /// </summary>
    public class PasswordAlgorithm {
        internal const bool CompareInConstantTimeDefault = true;
        internal const Int16 SaltLengthDefault = 16;
        internal const Int32 HashIterationsDefault = 1000;
        internal const HashFunction HashFunctionDefault = HashFunction.SHA256;

        /// <summary>
        /// This is the encoding used to convert a plain-text password
        /// into an array of bytes.
        /// </summary>
        private static readonly Encoding PasswordEncoding = Encoding.UTF8;

        /// <summary>
        /// The number of items in a byte array created from a 16-bit integer.
        /// </summary>
        private static readonly int Int16ByteLength = BitConverter.GetBytes(default(Int16)).Length;

        /// <summary>
        /// The number of items in a byte array created from a 32-bit integer.
        /// </summary>
        private static readonly int Int32ByteLength = BitConverter.GetBytes(default(Int32)).Length;

        /// <summary>
        /// Creates a new instance of <see cref="T:HashAlgorithm"/> for the specified <paramref name="hashFunction" />.
        /// </summary>
        /// <param name="hashFunction">
        /// The type of hash algorithm to create.
        /// </param>
        /// <returns>
        /// A new instance of <see cref="T:HashAlgorithm"/> for the specified <paramref name="hashFunction" />.
        /// </returns>
        private static HashAlgorithm CreateHashAlgorithm(HashFunction hashFunction) {
            switch (hashFunction) {
                case HashFunction.SHA256: return SHA256.Create();
                case HashFunction.SHA384: return SHA384.Create();
                case HashFunction.SHA512: return SHA512.Create();
                default: throw new ArgumentException(
                    string.Format("The {0} value {1} has not been implemented.", typeof(HashFunction), hashFunction),
                    "hashFunction"
                );
            }
        }

        /// <summary>
        /// Creates a hash of the <paramref name="password"/> using the specified parameters.
        /// </summary>
        /// <param name="password">The string for which the hash is created.</param>
        /// <param name="hashFunction">The type of hash function to use to create the hash.</param>
        /// <param name="hashIterations">The number of key-stretching iterations to complete when creating the hash.</param>
        /// <param name="saltBytes">The salt for <paramref name="password"/> as an array of bytes.</param>
        /// <returns>
        /// The created hash of the <paramref name="password"/>.
        /// </returns>
        private static string Compute(string password, HashFunction hashFunction, Int32 hashIterations, byte[] saltBytes) {
            if (null == saltBytes) throw new ArgumentNullException("saltBytes");

            // Gets the length of the salt as a byte array
            // so it can be added to the final computation.
            var saltLength = Convert.ToInt16(saltBytes.Length);
            var saltLengthBytes = BitConverter.GetBytes(saltLength);

            // Gets the type of hash function and the number
            // of iterations as byte arrays so they can be
            // added to the final computation.
            var hashFunctionBytes = BitConverter.GetBytes((short)hashFunction);
            var hashIterationBytes = BitConverter.GetBytes(hashIterations);

            // Converts the plain-text password into a byte array
            // and adds the specified salt.
            var passwordBytes = PasswordEncoding.GetBytes(password);
            var passwordAndSaltBytes = passwordBytes
                .Concat(saltBytes)
                .ToArray();

            // Creates the hash algorithm that is used to generate
            // the password hash.
            var hashBytes = default(byte[]);
            using (var hashAlgorithm = CreateHashAlgorithm(hashFunction)) {

                // The hash is initialized by hashing the password
                // and salt.
                hashAlgorithm.Initialize();
                hashBytes = hashAlgorithm.ComputeHash(passwordAndSaltBytes);

                // Performs key stretching over the specified number
                // of hash iterations.
                while (hashIterations-- > 0) {
                    
                    // The hash is modified during each iteration by
                    // computing another hash of the previous hash
                    // and the entered password.
                    hashBytes = hashBytes.Concat(passwordAndSaltBytes).ToArray();
                    hashBytes = hashAlgorithm.ComputeHash(hashBytes);
                }

                // The hashing algorithm isn't needed anymore.
                hashAlgorithm.Clear();
            }

            // Creates a single byte array of all the data
            // required to recreate the computation for the
            // given password.
            var computedResult = new byte[] { }
                .Concat(saltLengthBytes)
                .Concat(saltBytes)
                .Concat(hashFunctionBytes)
                .Concat(hashIterationBytes)
                .Concat(hashBytes)
                .ToArray();

            // Return the data encoded as a string.
            return Convert.ToBase64String(computedResult);
        }

        /// <summary>
        /// Gets or sets the object used to compare strings in constant time.
        /// </summary>
        internal IEqualityComparer<string> ConstantTimeComparer {
            get { return _ConstantTimeComparer ?? (_ConstantTimeComparer = new ConstantTimeComparer()); }
            set { _ConstantTimeComparer = value; }
        }
        private IEqualityComparer<string> _ConstantTimeComparer;

        /// <summary>
        /// Creates a new instance of <see cref="T:RandomNumberGenerator"/>.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="T:RandomNumberGenerator"/>.
        /// </returns>
        protected virtual RandomNumberGenerator CreateRandomNumberGenerator() {
            return RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Gets or sets a value that indicates whether or not a
        /// constant-time comparison is used when comparing a password
        /// to its computed result.
        /// </summary>
        public bool CompareInConstantTime {
            get { return _CompareInConstantTime; }
            set { _CompareInConstantTime = value; }
        }
        private bool _CompareInConstantTime = CompareInConstantTimeDefault;

        /// <summary>
        /// Gets or sets the <see cref="T:HashFunction"/> used while
        /// hashing new passwords.
        /// </summary>
        public HashFunction HashFunction {
            get { return _HashFunction; }
            set { _HashFunction = value; }
        }
        private HashFunction _HashFunction = HashFunctionDefault;

        /// <summary>
        /// Gets or sets the length, in bytes, of salts created
        /// for new passwords.
        /// </summary>
        public Int16 SaltLength {
            get { return _SaltLength; }
            set {
                if (0 > value) throw new ArgumentOutOfRangeException("SaltLength", "The salt length cannot be less than 0.");
                _SaltLength = value;
            }
        }
        private Int16 _SaltLength = SaltLengthDefault;

        /// <summary>
        /// Gets or sets the number of key-stretching iterations
        /// to perform while hashing new passwords.
        /// </summary>
        public Int32 HashIterations {
            get { return _HashIterations; }
            set {
                if (0 > value) throw new ArgumentOutOfRangeException("HashIterations", "The number of hash iterations cannot be less than 0.");
                _HashIterations = value;
            }
        }
        private Int32 _HashIterations = HashIterationsDefault;

        /// <summary>
        /// Creates a new instance of <see cref="T:PasswordAlgorithm"/>.
        /// </summary>
        public PasswordAlgorithm() {
            var configuration = SecurityConfiguration
                .Default
                .PasswordAlgorithmConfiguration;
            if (configuration != null) {
                SaltLength = configuration.SaltLength;
                HashFunction = configuration.HashFunction;
                HashIterations = configuration.HashIterations;
                CompareInConstantTime = configuration.CompareInConstantTime;
            }
        }

        /// <summary>
        /// Creates a string that can later be used in <see cref="PasswordAlgorithm.Compare"/>
        /// to determine password validity.
        /// </summary>
        /// <param name="password">
        /// The plain-text, user-entered string.
        /// </param>
        /// <returns>
        /// A string that can later be used in <see cref="PasswordAlgorithm.Compare"/>
        /// to determine password validity.
        /// </returns>
        public virtual string Compute(string password) {
            // First, generate a salt using a random number generator.
            var salt = new byte[SaltLength];
            using (var randomNumberGenerator = CreateRandomNumberGenerator()) {
                randomNumberGenerator.GetBytes(salt);
            }

            // Now, perform the same computation that is later performed
            // when comparing passwords. We pass the current hash function
            // and key-stretching iteration count so they get saved in the
            // computed result.
            return Compute(password, HashFunction, HashIterations, salt);
        }

        /// <summary>
        /// Compares the plain-text <paramref name="password"/> to the
        /// <paramref name="computedResult"/> that was computed using
        /// an instance of this <see cref="T:PasswordAlgorithm"/>.
        /// </summary>
        /// <param name="password">
        /// The plain-text, user-entered string.
        /// </param>
        /// <param name="computedResult">
        /// The result of a previous call to <see cref="PasswordAlgorithm.Compute(string)"/>
        /// using <paramref name="password"/> as the parameter.
        /// </param>
        /// <returns>
        /// <c>true</c> if the <paramref name="password"/> is the same as the
        /// parameter to <see cref="PasswordAlgorithm.Compute(string)"/> that returned
        /// the <paramref name="computedResult"/>. Otherwise, <c>false</c>.
        /// </returns>
        public virtual bool Compare(string password, string computedResult) {

            // All of the password data is encoded as a base-64
            // string, so we start by getting that data as a
            // byte array.
            var bytes = Convert.FromBase64String(computedResult);

            // The first group of bytes identifies how long the
            // password's salt is. Once we know how long it is,
            // we can get the actual salt.
            var saltLengthBytes = bytes.Take(Int16ByteLength).ToArray();
            var saltLength = BitConverter.ToInt16(saltLengthBytes, 0);
            var saltBytes = bytes
                .Skip(Int16ByteLength)
                .Take(saltLength)
                .ToArray();

            // The next group of bytes identifies the hash function
            // that was used when the password was created.
            var hashFunctionBytes = bytes
                .Skip(Int16ByteLength + saltLength)
                .Take(Int16ByteLength)
                .ToArray();
            var hashFunction = (HashFunction)BitConverter.ToInt16(hashFunctionBytes, 0);

            // And the last encoded group identifies the number of
            // key-stretching iterations to perform.
            var hashIterationBytes = bytes
                .Skip(Int16ByteLength + saltLength + Int16ByteLength)
                .Take(Int32ByteLength)
                .ToArray();
            var hashIterations = BitConverter.ToInt32(hashIterationBytes, 0);

            // The salt, hash function, and number of key-stretching 
            // iterations are known, so we can compute the password 
            // using the same algorithm with which it was created.
            var expectedResult = Compute(password, hashFunction, hashIterations, saltBytes);

            // Return whether or not the strings are equal. If
            // the flag is set, then do the comparison in constant
            // time.
            return CompareInConstantTime
                ? ConstantTimeComparer.Equals(expectedResult, computedResult)
                : string.Equals(expectedResult, computedResult);
        }
    }
}
