using System;
using System.Collections.Generic;
using System.Linq;

namespace Ensues.Security.Cryptography {

    /// <summary>
    /// An equality comparer that compares strings in constant time.
    /// </summary>
    internal class ConstantTimeComparer : IEqualityComparer<string> {
        
        /// <summary>
        /// Helper method to extend <paramref name="s"/> by <paramref name="count"/> characters.
        /// </summary>
        /// <param name="s">The string to be extended.</param>
        /// <param name="count">The number of characters by which <paramref name="s"/> is extended.</param>
        /// <returns>
        /// A string made up of <paramref name="s"/> followed by the specified <paramref name="count"/>
        /// of characters.
        /// </returns>
        private static string Extend(string s, int count) {
            return s + new string(Enumerable.Range(0, count).Select(_ => '_').ToArray());
        }

        /// <summary>
        /// Get the default instance of this comparer class.
        /// </summary>
        public static ConstantTimeComparer Default { get { return _Default; } }
        private static readonly ConstantTimeComparer _Default = new ConstantTimeComparer();

        /// <summary>
        /// Determines if <paramref name="x"/> equals <paramref name="y"/>.
        /// </summary>
        /// <param name="x">The left string in the equality check.</param>
        /// <param name="y">The right string in the equality check.</param>
        /// <returns>
        /// Boolean <c>true</c> if <paramref name="x"/> equals <paramref name="y"/>.
        /// Otherwise, <c>false</c>.
        /// </returns>
        public bool Equals(string x, string y) {

            // Ensures that both variables are actual
            // instances of strings.
            var s1 = x ?? string.Empty;
            var s2 = y ?? string.Empty;

            // Gets the length of both strings. The shorter
            // string will be extended by the difference in
            // characters so that this method always takes the
            // same amount of time to compare a string of the
            // longer string's length.
            var s1len = s1.Length;
            var s2len = s2.Length;

            // Extends the length of s1 if s2 is longer
            if (s1len < s2len) {
                s1 = Extend(s1, s2len - s1len);
            }

            // Extends the length of s2 if s1 is longer
            if (s2len < s1len) {
                s2 = Extend(s2, s1len - s2len);
            }

            // Compares each character in s1 to the
            // corresponding character (by index) in
            // s2.
            var diff = (uint)0;
            var slen = s1.Length;
            for (var i = 0; i < slen; i++) {
                var c1 = s1[i];
                var c2 = s2[i];
                var xor = c1 ^ c2;
                diff |= (uint)xor;
            }

            // Checks first if either parameter was null.
            // If so, then they both have to be null for
            // the strings to be equal. Otherwise, they
            // have to have the same lengths, and they
            // have to have no differences by character
            // comparison.
            return x == null || y == null
                ? x == null && y == null
                : s1len == s2len && diff == 0;
        }

        public int GetHashCode(string obj) {
            throw new NotSupportedException();
        }
    }
}
