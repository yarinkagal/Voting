using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ServiceFabric.Data.Collections;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using Azure.Storage.Blobs;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Consumer;
using Azure.Messaging.EventHubs.Processor;
using System.Text;
using System.IO;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Newtonsoft.Json;
using VotingWeb;

namespace VotingDataNew
{
    /// <summary>
    /// An instance of this class is created for each service replica by the Service Fabric runtime.
    /// </summary>
    internal sealed class VotingDataNew : StatefulService
    {

        public TrafficManager manager;

        public VotingDataNew(StatefulServiceContext context)
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

                            manager.getFromEH();

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
