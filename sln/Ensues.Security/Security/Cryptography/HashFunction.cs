using System;

namespace Ensues.Security.Cryptography {

    /// <summary>
    /// Enumeration whose values map to a type of <see cref="T:HashAlgorithm"/>.
    /// </summary>
    public enum HashFunction : short {

        /// <summary>
        /// Represents the <see cref="T:SHA256"/> hash algorithm.
        /// </summary>
        SHA256,

        /// <summary>
        /// Represents the <see cref="T:SHA384"/> hash algorithm.
        /// </summary>
        SHA384,

        /// <summary>
        /// Represents the <see cref="T:SHA512"/> hash algorithm.
        /// </summary>
        SHA512
    }
}
