using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;
using System.Text;
using Newtonsoft.Json;
using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace VotingWeb.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class VotesController : Controller
    {

        TrafficManager manager;
        private readonly ILogger<VotesController> _logger;
        private TraceLog traceLog;
        private InventoryRepository inventory;


        public VotesController(ILogger<VotesController> logger)
        {
            _logger = logger;
        }



        //[HttpGet]
        ////public async Task<List<InventoryItem>> Get()
        //public ActionResult<IEnumerable<InventoryItem>> Get()
        //{
        //    if(manager==null)
        //        manager = new TrafficManager();

        //    // return manager.GetAllData();

        //    var result = this.manager.GetAllData();
        //    //this.traceLog.LogInfo("Inventory.GetAll", $"Getting array of {result.Length} items");
        //    return result;

        //}

        //[HttpGet("{name}")]
        //public async Task<InventoryItem> Get(string name )
        //{
        //    if (manager == null)
        //        manager = new TrafficManager();

        //    return manager.GetOneData(name);

        //}


        //[HttpPut("{id}")]
        //public async Task<object> Put(string id, [FromBody] string content)
        //{


        //    if (manager == null)
        //        manager = new TrafficManager();

        //    InventoryItem data = new InventoryItem(id, content);
        //    //string json = JsonConvert.SerializeObject(data);
        //    manager.sendToEH(id , data );


        //    return data;
        //}


        //[HttpDelete("{name}")]
        //public async Task<string> Delete(string name)
        //{
        //    if (manager == null)
        //        manager = new TrafficManager();
           
        //    manager.sendToEH(name,null);

        //    return $"{name} deleted";
        //}
    }
}
