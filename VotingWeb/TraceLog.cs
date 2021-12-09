using Microsoft.Cloud.InstrumentationFramework;

namespace VotingWeb
{
    public class TraceLog 
    {
        private const string SessionName = "Inventory";

        public TraceLog()
        {
            // IFx initialization is a required step for emitting logs
            IfxInitializer.IfxInitialize(SessionName);
        }

        public void LogInfo(string tagId, string message)
        {
            IfxTracer.LogMessage(IfxTracingLevel.Informational, tagId, message);
        }

        public void LogError(string tagId, string message)
        {
            IfxTracer.LogMessage(IfxTracingLevel.Error, tagId, message);
        }
    }
}
