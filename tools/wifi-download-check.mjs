// Bounded NDT7 download diagnostic. Requires Node with built-in WebSocket.
// Usage: node tools/wifi-download-check.mjs [--ipv4]
// Uses M-Lab's public measurement service; its normal data policy applies.
// Only aggregate metrics are printed, never access tokens or client addresses.
import dns from 'node:dns';

if (process.argv.includes('--ipv4')) dns.setDefaultResultOrder('ipv4first');
const deadline = setTimeout(() => {
  console.error('Download diagnostic exceeded 25 seconds');
  process.exit(1);
}, 25000);
try {
  const response = await fetch(
    'https://locate.measurementlab.net/v2/nearest/ndt/ndt7?client_name=t2-wifi-diagnostic&time=' + Date.now(),
    { signal: AbortSignal.timeout(10000) },
  );
  if (!response.ok) throw new Error(`Server discovery HTTP ${response.status}`);
  const server = (await response.json()).results[0];
  console.log('Server:', server.hostname);
  const ws = new WebSocket(server.urls['wss:///ndt/v7/download'], 'net.measurementlab.ndt.v7');
  ws.binaryType = 'arraybuffer';
  let start, bytes = 0, last;
  ws.onopen = () => { start = performance.now(); };
  ws.onmessage = ({ data }) => {
    if (typeof data === 'string') {
      try { last = JSON.parse(data); } catch { /* Ignore malformed optional metrics. */ }
    } else bytes += data.byteLength;
  };
  ws.onerror = () => { console.error('WebSocket failed'); process.exit(1); };
  ws.onclose = ({ code }) => {
    clearTimeout(deadline);
    if (code !== 1000 || !start || !bytes) {
      console.error(`Incomplete test (close code ${code})`);
      process.exitCode = 1;
      return;
    }
    const seconds = (performance.now() - start) / 1000;
    console.log(JSON.stringify({
      seconds: +seconds.toFixed(2), Mbps: +(bytes * 8 / seconds / 1e6).toFixed(1),
      family: last?.ConnectionInfo?.Client?.startsWith('[') ? 'IPv6' : 'IPv4',
      minRttMs: last?.TCPInfo?.MinRTT / 1000,
      retransmissions: last?.TCPInfo?.TotalRetrans,
      segmentsSent: last?.TCPInfo?.DataSegsOut,
    }));
  };
} catch (error) {
  clearTimeout(deadline);
  console.error(error.message);
  process.exitCode = 1;
}
