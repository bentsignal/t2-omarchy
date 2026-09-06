// SPDX-License-Identifier: MIT
// Presentation only: no state in this file may grant authentication.
function parse(text) {
    try {
        var value = JSON.parse(text);
        return value && value.schema_version === 1 ? value : {};
    } catch (_) { return {}; }
}

function describe(transport, scan, now) {
    var transportAge = now - Number(transport.updated_at) * 1000;
    var scanAge = now - Number(scan.updated_at) * 1000;
    var validTransport = transport.schema_version === 1 && transport.channel === "transport";
    var waiting = validTransport && (transport.state === "sleeping" || transport.state === "recovering");
    if (waiting && transportAge >= 0 && transportAge < 90000)
        return { text: "Touch ID waking up — password available", ready: false, waitingForTransport: true };
    if (!validTransport || transport.state !== "available")
        return { text: "Touch ID unavailable — use password", ready: false, waitingForTransport: false };
    if (scan.schema_version === 1 && scan.channel === "scan" && scan.state === "ready" && scanAge >= 0 && scanAge < 25000 && Number(scan.updated_at) >= Number(transport.updated_at))
        return { text: "Touch and hold your finger to unlock", ready: true, waitingForTransport: false };
    if (scan.state === "unavailable")
        return { text: "Touch ID unavailable — use password", ready: false, waitingForTransport: false };
    return { text: "Touch ID preparing — password available", ready: false, waitingForTransport: false };
}
