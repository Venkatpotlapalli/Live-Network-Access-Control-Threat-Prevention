// Hide page loader when content is fully loaded
document.addEventListener("DOMContentLoaded", () => {
    const loader = document.getElementById("soc-page-loader");
    if (loader) {
        // Add a small delay so the animation feels complete
        setTimeout(() => {
            loader.style.opacity = "0";
            loader.style.transition = "opacity 0.5s ease";
            setTimeout(() => {
                loader.style.display = "none";
            }, 500); // Wait for transition to finish
        }, 300);
    }
});
