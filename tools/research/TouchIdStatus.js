// SPDX-License-Identifier: MIT
// Presentation only: no state in this file may grant authentication.
function parse(text) {
    try {
        var value = JSON.parse(text);
        return value && value.schema_version === 1 ? value : {};
    } catch (_) { return {}; }
}

function recoveredAfter(transport, cutoff) {
    return transport.schema_version === 1 && transport.channel === "transport" &&
        transport.state === "available" && Number(transport.updated_at) > cutoff;
}

function describe(transport, scan, now, refreshing, scanNotBefore, preparingSleep) {
    if (preparingSleep)
        return { text: "Touch ID waking up — password available", ready: false, waitingForTransport: true };
    if (refreshing)
        return { text: "Checking Touch ID — password available", ready: false, waitingForTransport: true };
    var transportAge = now - Number(transport.updated_at) * 1000;
    var scanAge = now - Number(scan.updated_at) * 1000;
    var validTransport = transport.schema_version === 1 && transport.channel === "transport";
    var waiting = validTransport && (transport.state === "sleeping" || transport.state === "recovering");
    // Sleep may last hours; its pre-sleep timestamp must not enable a new PAM
    // attempt before the resume service has published recovery/availability.
    if (waiting && transportAge >= 0 && (transport.state === "sleeping" || transportAge < 90000))
        return { text: "Touch ID waking up — password available", ready: false, waitingForTransport: true };
    if (!validTransport || transport.state !== "available")
        return { text: "Touch ID unavailable — use password", ready: false, waitingForTransport: false };
    if (scan.schema_version === 1 && scan.channel === "scan" && scan.state === "ready" && scanAge >= 0 && scanAge < 25000 && Number(scan.updated_at) >= Number(transport.updated_at) && Number(scan.updated_at) >= (scanNotBefore || 0))
        return { text: "Touch and hold your finger to unlock", ready: true, waitingForTransport: false };
    if (scan.state === "unavailable")
        return { text: "Touch ID unavailable — use password", ready: false, waitingForTransport: false };
    return { text: "Touch ID preparing — password available", ready: false, waitingForTransport: false };
}
