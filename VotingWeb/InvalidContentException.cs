using System;
using System.Runtime.Serialization;

namespace VotingWeb
{
    [Serializable]
    internal class InvalidContentException : Exception
    {
        public InvalidContentException()
        {
        }

        public InvalidContentException(string message) : base(message)
        {
        }

        public InvalidContentException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidContentException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}