using System;
using System.Collections.Generic;
using System.Fabric;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.ServiceFabric.Services.Communication.AspNetCore;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using Microsoft.ServiceFabric.Data;
using VotingWeb;
using VotingWeb.Controllers;

namespace VotingData
{
    /// <summary>
    /// The FabricRuntime creates an instance of this class for each service type instance. 
    /// </summary>

    

    internal sealed class VotingData : StatefulService
    {
        public TrafficManager manager;
        public VotingData(StatefulServiceContext context)
            : base(context)
        {
            manager = new TrafficManager();
        }



        protected override IEnumerable<ServiceReplicaListener> CreateServiceReplicaListeners()
        {
            return new ServiceReplicaListener[0];
        }

        protected override Task RunAsync(CancellationToken cancellationToken)
        {
            return Task.Factory.StartNew(
                async () =>
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            if (manager == null)
                                manager = new TrafficManager();
                            manager.getFromEH();
                            manager.traceLog.LogInfo("TrafficManager.DataAccepted", "TrafficManager got data from event hub");

                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Exception: {e}");
                            throw;
                        }
                    }
                },
                cancellationToken,
                TaskCreationOptions.None,
                TaskScheduler.Default);
        }
    }
}

