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
using Azure.Messaging.EventHubs.Producer;
using System.Text;
using Newtonsoft.Json;
using System.IO;
using Azure.Storage.Blobs.Models;
using Azure;
using System.Collections;
using Azure.Storage;
using Azure.Storage.Blobs;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.WindowsAzure.Storage;

namespace VotingWeb
    {
    /// <summary>
    /// An instance of this class is created for each service replica by the Service Fabric runtime.
    /// </summary>
    public class TrafficManager 
    {
        private const string ehubNamespaceConnectionString = "Endpoint=sb://yarinkagalns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=cX2O4D8Po+3BEd3QUWkCC7SRXa9Te1tpk3ScCaeESfY=";

        

        private const string eventHubName = "yarinkagaleh";
        private const string blobStorageConnectionString = "DefaultEndpointsProtocol=https;AccountName=yarinkagalsa;AccountKey=QTetx8CQ2M8Eg0Uhik1W9HVQPS0VIcLLwk/F7kNkANVnKstFa87mnjyPqg8TPPJZ1nNhOBigiz4IpUH/AmoXMA==;EndpointSuffix=core.windows.net";
        
        private const string eventsContainerName = "containerdrill1";
        private const string dataContainerName = "datacontainer"; 


        static BlobContainerClient EHStorageClient;

        

        static BlobContainerClient DataStorageClient = new BlobContainerClient(blobStorageConnectionString, dataContainerName);
        static EventProcessorClient processor;
        static EventHubProducerClient producerClient;

        public CloudStorageAccount storageAccount = CloudStorageAccount.Parse(blobStorageConnectionString);
        public CloudBlobClient serviceClient;
        public CloudBlobContainer container;

        public TraceLog traceLog;


        public TrafficManager()
        {
           serviceClient = storageAccount.CreateCloudBlobClient();
           container = serviceClient.GetContainerReference($"{dataContainerName}");
            this.traceLog = traceLog = new TraceLog();

    }

        internal InventoryItem GetOneData(string name)
        {
            CloudBlockBlob file = container.GetBlockBlobReference(name);
            string content = file.DownloadTextAsync().Result;

            return JsonConvert.DeserializeObject<InventoryItem>(content);
        }
        public InventoryItem[] GetAllData()
        {
            // ask the data container for all the blobs
            // for each blob, deserialize and add to the list
            // return the list
            
           
            var blobs = DataStorageClient.GetBlobs();

            List<InventoryItem> datas = new List<InventoryItem>();
            foreach (BlobItem blobItem in blobs)
            {
                CloudBlockBlob file = container.GetBlockBlobReference(blobItem.Name);
                string content = file.DownloadTextAsync().Result;
                InventoryItem data = JsonConvert.DeserializeObject<InventoryItem>(content);
                datas.Add(data);
                this.traceLog.LogInfo("TrafficManager.DataOut", "TrafficManager got data from storage");

            }

            return datas.ToArray();
        }


        

        public async void sendToEH( string id, InventoryItem data)
        {
            //string output; 

            producerClient = new EventHubProducerClient(ehubNamespaceConnectionString, eventHubName);

            using EventDataBatch eventBatch = await producerClient.CreateBatchAsync();


            //string output = JsonConvert.SerializeObject(data);
            string output = System.Text.Json.JsonSerializer.Serialize(data);
            // add to eh
            if (!eventBatch.TryAdd(new EventData(Encoding.UTF8.GetBytes(output))))
            {
                // if it is too large for the batch
                throw new Exception("Event is too large for the batch and cannot be sent.");
            }


            try
            {
                // Use the producer client to send the batch of events to the event hub
                await producerClient.SendAsync(eventBatch);
                this.traceLog.LogInfo("TrafficManager.DataOut", $"TrafficManager sent data(id = {id}) to event hub ");

            }
            finally
            {
                await producerClient.DisposeAsync();
            }

            Console.WriteLine("wrote to EH");
            
        }



        public async Task getFromEH()
        {
            // Read from the default consumer group: $Default
            string consumerGroup = EventHubConsumerClient.DefaultConsumerGroupName;

            // Create a blob container client that the event processor will use 
            EHStorageClient = new BlobContainerClient(blobStorageConnectionString, eventsContainerName);


            // Create an event processor client to process events in the event hub
            processor = new EventProcessorClient(EHStorageClient, consumerGroup, ehubNamespaceConnectionString, eventHubName);

            // Register handlers for processing events and handling errors
            processor.ProcessEventAsync += ProcessEventHandler;
            processor.ProcessErrorAsync += ProcessErrorHandler;
            
            // Start the processing
            await processor.StartProcessingAsync();

            // Wait for 30 seconds for the events to be processed
            await Task.Delay(TimeSpan.FromSeconds(30));

            // Stop the processing
            await processor.StopProcessingAsync();
        }

        static async Task ProcessEventHandler(ProcessEventArgs eventArgs)
        {
            byte[] byteArray = eventArgs.Data.Body.ToArray();
            string jsonString = Encoding.UTF8.GetString(byteArray);
            InventoryItem data = JsonConvert.DeserializeObject<InventoryItem>(jsonString);
            CloudBlockBlob file=null;

            try
            {
                DataStorageClient = new BlobContainerClient(blobStorageConnectionString, dataContainerName);

                CloudStorageAccount storageAccount = CloudStorageAccount.Parse(blobStorageConnectionString);
                CloudBlobClient serviceClient = storageAccount.CreateCloudBlobClient();
                CloudBlobContainer container = serviceClient.GetContainerReference($"{dataContainerName}");

                file = container.GetBlockBlobReference(data.Id);
                //this.traceLog.LogInfo("TrafficManager.DataAccepted", $"TrafficManager sent data(id = {data.Id}) to storage ");


            }
            catch (Exception e)
            {
                Console.WriteLine(e);

            }


           
            MemoryStream stream = new MemoryStream(byteArray);

            try
            {
                if (data == null)
                {
                    file.DeleteIfExistsAsync();
                    return;
                }
                else
                {
                    await file.UploadFromStreamAsync(stream);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            // Update checkpoint in the blob storage so that the app receives only new events the next time it's run
            await eventArgs.UpdateCheckpointAsync(eventArgs.CancellationToken);

        }

        static Task ProcessErrorHandler(ProcessErrorEventArgs eventArgs)
        {
            // Write details about the error to the console window
            Console.WriteLine($"\tPartition '{ eventArgs.PartitionId}': an unhandled exception was encountered. This was not expected to happen.");
            Console.WriteLine(eventArgs.Exception.Message);
            return Task.CompletedTask;
        }






        public string deleteVote(string name)
        {
            try
            {
                container.GetBlockBlobReference(name).DeleteIfExistsAsync();
                return "Succeeded";
            }
            catch
            {
                return "Failed";
            }
        }
    }
}
