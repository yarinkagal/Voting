//using System;
//using System.Collections.Generic;
//using System.Fabric;
//using System.Linq;
//using System.Threading;
//using System.Threading.Tasks;
//using Microsoft.ServiceFabric.Data.Collections;
//using Microsoft.ServiceFabric.Services.Communication.Runtime;
//using Microsoft.ServiceFabric.Services.Runtime;
//using Azure.Storage.Blobs;
//using Azure.Messaging.EventHubs;
//using Azure.Messaging.EventHubs.Consumer;
//using Azure.Messaging.EventHubs.Processor;
//using Azure.Messaging.EventHubs.Producer;
//using System.Text;
//using Newtonsoft.Json;
//namespace TrafficManager
//{
//    /// <summary>
//    /// An instance of this class is created for each service replica by the Service Fabric runtime.
//    /// </summary>
//    public class TrafficManager : StatefulService
//    {
//        private const string ehubNamespaceConnectionString = "Endpoint=sb://yarinkagalns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=WsFrCZODtXW4kBpjZZgRe+BzGuvLgVm3Eu/m0+RlZXk=";
//        private const string eventHubName = "yarinkagaleh";
//        private const string blobStorageConnectionString = "DefaultEndpointsProtocol=https;AccountName=yarinkagalsa;AccountKey=SBW1RfCKzylGbXCWuFM+dipoysSb3AG92XZAoFckeIX36brJ5x+F3qG4J2hXO2dsIaCmHmEqZyj4q3+eOk8ZXA==;EndpointSuffix=core.windows.net";
//        private const string blobContainerName = "containerdrill1";


//        static BlobContainerClient storageClient;
      
//        static EventProcessorClient processor;

//        static EventHubProducerClient producerClient;

//        public TrafficManager(StatefulServiceContext context)
//            : base(context)
//        { }



//        internal class Vote
//        {
//            public string name { get; set; }

//            public int rate { get; set; }

//        }


//        static async Task sendToEH(Vote vote)
//        {
//            string output = JsonConvert.SerializeObject(vote);


//            String temp = vote.name;
//            Console.WriteLine(temp);
//            // Create a producer client that you can use to send events to an event hub
//            producerClient = new EventHubProducerClient(ehubNamespaceConnectionString, eventHubName);

//            // Create a batch of events 
//            using EventDataBatch eventBatch = await producerClient.CreateBatchAsync();

//            // add to eh
//            if (!eventBatch.TryAdd(new EventData(Encoding.UTF8.GetBytes(output))))
//            {
//                // if it is too large for the batch
//                throw new Exception("Event is too large for the batch and cannot be sent.");
//            }


//            try
//            {
//                // Use the producer client to send the batch of events to the event hub
//                await producerClient.SendAsync(eventBatch);
//            }
//            finally
//            {
//                await producerClient.DisposeAsync();
//            }

//            Console.WriteLine("wrote to EH");
//        }


        
        
//    }
//}
