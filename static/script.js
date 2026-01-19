// --- TERMS AND CONDITIONS GATEKEEPER ---
document.addEventListener("DOMContentLoaded", function() {
    // 1. Check if user has already accepted
    if (!localStorage.getItem("termsAccepted")) {
        // 2. If not, show the modal
        document.getElementById("termsModal").style.display = "flex";
        // 3. Disable scrolling so they focus on the modal
        document.body.style.overflow = "hidden";
    }
});

function acceptTerms() {
    // 1. Save the "Accepted" flag to the browser memory
    localStorage.setItem("termsAccepted", "true");
    
    // 2. Hide the modal
    document.getElementById("termsModal").style.display = "none";
    
    // 3. Re-enable scrolling
    document.body.style.overflow = "auto";
}

function declineTerms() {
    alert("Access Denied. You must accept the protocols to use this system.");
    // Optional: Redirect them away
    window.location.href = "https://www.google.com";
}

// ... (Rest of your Scanner logic below) ...
// --- Mobile Nav Logic ---
function toggleNav() {
    const nav = document.getElementById("mobileNav");
    if (nav.style.width === "100%") {
        nav.style.width = "0%";
    } else {
        nav.style.width = "100%";
    }
}

// --- Scanner Logic ---
async function startScan() {
    const user = document.getElementById('username').value;
    const resultsDiv = document.getElementById('results');
    const loader = document.getElementById('loader');

    if(!user) return alert("Enter a username!");

    resultsDiv.innerHTML = '';
    loader.classList.remove('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: user})
        });

        const data = await response.json();
        loader.classList.add('hidden');

        // Logic: Check if we found ANYTHING
        if (data.length === 0) {
            resultsDiv.innerHTML = `
                <div class="card" style="text-align:center; color:#888;">
                    <span>NO DIGITAL FOOTPRINT DETECTED.</span>
                </div>
            `;
            return;
        }

        // Render only the found items
        data.forEach((item, index) => {
            const div = document.createElement('div');
            div.style.animationDelay = `${index * 0.1}s`;
            // Note: 'status-found' is now default because we only show found items
            div.className = `card slide-up found`; 
            
            div.innerHTML = `
                <span>${item.site}</span>
                <a href="${item.url}" target="_blank">PROFILE DETECTED ↗</a>
            `;
            resultsDiv.appendChild(div);
        });

    } catch (e) {
        loader.classList.add('hidden');
        alert("System Error. Please try again.");
    }
}
