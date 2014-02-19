using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Ensues.Security.Cryptography {

    public class PasswordAlgorithm {

        private static readonly Encoding PasswordEncoding = Encoding.UTF8;
        private static readonly int Int16ByteLength = BitConverter.GetBytes(default(Int16)).Length;
        private static readonly int Int32ByteLength = BitConverter.GetBytes(default(Int32)).Length;

        private string Compute(string password, HashFunction hashFunction, Int32 hashIterations, byte[] salt) {
            if (null == salt) throw new ArgumentNullException("salt");

            var passwordBytes = PasswordEncoding.GetBytes(password);
            var passwordAndSalt = passwordBytes
                .Concat(salt)
                .ToArray();

            var hash = default(byte[]);
            using (var algo = CreateHashAlgorithm(hashFunction)) {

                algo.Initialize();
                hash = algo.ComputeHash(passwordAndSalt);

                foreach (var _ in Enumerable.Range(0, hashIterations)) {
                    
                    hash = algo.ComputeHash(
                        hash.Concat(passwordBytes).ToArray()
                    );
                }

                algo.Clear();
            }

            var saltLength = salt.Length;
            var saltLengthBytes = BitConverter.GetBytes(saltLength);

            var hashFunctionBytes = BitConverter.GetBytes((short)hashFunction);
            var hashIterationBytes = BitConverter.GetBytes(hashIterations);

            var passwordData = new byte[] { }
                .Concat(saltLengthBytes)
                .Concat(salt)
                .Concat(hashFunctionBytes)
                .Concat(hashIterationBytes)
                .Concat(hash)
                .ToArray();

            return Convert.ToBase64String(passwordData);
        }

        protected virtual HashAlgorithm CreateHashAlgorithm(HashFunction hashFunction) {

            switch (hashFunction) {

                case HashFunction.SHA1:
                    return SHA1.Create();

                case HashFunction.SHA256:
                    return SHA256.Create();

                case HashFunction.SHA512:
                    return SHA512.Create();

                default:
                    var msg = string.Format("The {0} value {1} has not been implemented.", typeof(HashFunction), hashFunction);
                    throw new NotImplementedException(msg);
            }
        }

        protected virtual RandomNumberGenerator CreateRandomNumberGenerator() {
            return RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Gets or sets the <see cref="T:HashFunction"/> used while
        /// hashing new passwords.
        /// </summary>
        public HashFunction HashFunction {
            get { return _HashFunction; }
            set { _HashFunction = value; }
        }
        private HashFunction _HashFunction = HashFunction.SHA512;

        /// <summary>
        /// Gets or sets the length, in bytes, of salts created
        /// for new passwords.
        /// </summary>
        public Int32 SaltLength {
            get { return _SaltLength; }
            set { _SaltLength = value; }
        }
        private Int32 _SaltLength = 16;

        /// <summary>
        /// Gets or sets the number of key-stretching iterations
        /// to perform while hashing new passwords.
        /// </summary>
        public Int32 HashIterations {
            get { return _HashIterations; }
            set { _HashIterations = value; }
        }
        private Int32 _HashIterations = 1000;

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
        public string Compute(string password) {

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
        /// Compares the user-entered <paramref name="password"/> to the
        /// <paramref name="computedResult"/> that was computed using
        /// an instance of this <see cref="T:PasswordAlgorithm"/>.
        /// </summary>
        /// <param name="password">
        /// The plain-text, user-entered string.
        /// </param>
        /// <param name="computedResult">
        /// The result of a previous call to <see cref="PasswordAlgorithm.Compute"/>
        /// using <paramref name="password"/> as the parameter.
        /// </param>
        /// <returns>
        /// <c>true</c> if the <paramref name="password"/> is the same as the
        /// parameter to <see cref="PasswordAlgorithm.Compute"/> that returned
        /// the <paramref name="computedResult"/>. Otherwise, <c>false</c>.
        /// </returns>
        public bool Compare(string password, string computedResult) {

            // All of the password data is encoded as a base-64
            // string, so we start by getting that data as a
            // byte array.
            var bytes = Convert.FromBase64String(computedResult);

            // The first group of bytes identifies how long the
            // password's salt is. Once we know how long it is,
            // we can get the actual salt.
            var saltLengthBytes = bytes.Take(Int32ByteLength).ToArray();
            var saltLength = BitConverter.ToInt32(saltLengthBytes, 0);
            var salt = bytes
                .Skip(Int32ByteLength)
                .Take(saltLength)
                .ToArray();

            // The next group of bytes identifies the hash function
            // that was used when the password was created.
            var hashFunctionBytes = bytes
                .Skip(Int32ByteLength + saltLength)
                .Take(Int16ByteLength)
                .ToArray();
            var hashFunction = (HashFunction)BitConverter.ToInt16(hashFunctionBytes, 0);

            // And the last encoded group identifies the number of
            // key-stretching iterations to perform.
            var hashIterationBytes = bytes
                .Skip(Int32ByteLength + saltLength + Int16ByteLength)
                .Take(Int32ByteLength)
                .ToArray();
            var hashIterations = BitConverter.ToInt32(hashIterationBytes, 0);

            // The salt, hash function, and number of key-stretching 
            // iterations are known, so we can compute the password 
            // using the same algorithm with which it was created.
            var expected = Compute(password, hashFunction, hashIterations, salt);
            var actual = computedResult;

            return string.Equals(expected, actual);
        }
    }
}
