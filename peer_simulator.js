const sim = require('./node/peer_simulator.js');
if (typeof sim.runSimulation === 'function') {
  sim.runSimulation();
}
