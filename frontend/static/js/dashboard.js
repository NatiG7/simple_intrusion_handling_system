const tableBody = document.querySelector("#logTable tbody");
const simulateBtn = document.getElementById("simulate");

function randomIP() {
    return Array(4).fill(0).map(() => Math.floor(Math.random() * 256)).join(".");
}

function simulatePacket() {
    const timestamp = new Date().toLocaleTimeString();
    const src = randomIP();
    const dst = randomIP();
    const protocols = ["TCP", "IP"];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];

    const isAlert = protocol === "TCP" && Math.random() < 0.2;

    const row = document.createElement("tr");
    if (isAlert) row.classList.add("alert");

    row.innerHTML = `
        <td>${timestamp}</td>
        <td>${src}</td>
        <td>${dst}</td>
        <td>${protocol}</td>
        <td>${isAlert ? "⚠️ Suspicious" : "OK"}</td>
    `;

    tableBody.appendChild(row);
}

simulateBtn.addEventListener("click", simulatePacket);
