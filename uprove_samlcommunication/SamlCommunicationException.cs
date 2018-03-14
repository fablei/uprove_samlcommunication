using System;

namespace uprove_samlcommunication
{
    public enum SamlCommunicationType { SAMLCOMMUNICATION, SAMLARCHIVE, SAMLMETADATA, SAMLSERIALIZATION, SAMLVERIFICATION }

    public class SamlCommunicationException : Exception
    {
        public SamlCommunicationException()
            : base()
        {
        }

        /// <summary>
        /// Creates an error message and tells in which part the error message was thrown
        /// </summary>
        /// <param name="message">error message</param>
        /// <param name="type">thrown in</param>
        public SamlCommunicationException(string message, SamlCommunicationType type = SamlCommunicationType.SAMLCOMMUNICATION)
            : base(type + ": " + message)
        {
        }

        /// <summary>
        /// Creates an error message and tells in which part the error message was thrown
        /// </summary>
        /// <param name="message">error message</param>
        /// <param name="inner"></param>
        /// <param name="type">thrown in</param>
        public SamlCommunicationException(string message, Exception inner, SamlCommunicationType type = SamlCommunicationType.SAMLCOMMUNICATION)
            : base(type + ": " + message, inner)
        {
        }
    }
}
