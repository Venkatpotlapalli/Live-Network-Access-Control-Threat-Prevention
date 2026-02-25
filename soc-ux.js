(function () {
    "use strict";

    const loaderEl = document.getElementById("soc-page-loader");

    function hideLoader() {
        if (!loaderEl) {
            return;
        }
        loaderEl.classList.add("is-hidden");
        window.setTimeout(() => {
            if (loaderEl && loaderEl.parentNode) {
                loaderEl.parentNode.removeChild(loaderEl);
            }
        }, 340);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function () {
            window.setTimeout(hideLoader, 220);
        });
    } else {
        window.setTimeout(hideLoader, 220);
    }

    window.addEventListener("load", function () {
        window.setTimeout(hideLoader, 120);
    });

    document.querySelectorAll("form[data-loading-submit='true']").forEach((form) => {
        form.addEventListener("submit", () => {
            const submitButton = form.querySelector("button[type='submit']");
            if (!submitButton || submitButton.disabled) {
                return;
            }

            submitButton.dataset.originalHtml = submitButton.innerHTML;
            submitButton.disabled = true;
            submitButton.innerHTML =
                "<span class='spinner-border spinner-border-sm me-2' role='status' aria-hidden='true'></span>Processing...";

            window.setTimeout(() => {
                if (!submitButton.dataset.originalHtml) {
                    return;
                }
                submitButton.disabled = false;
                submitButton.innerHTML = submitButton.dataset.originalHtml;
            }, 8000);
        });
    });

    window.socAlert = function socAlert(options) {
        const payload = Object.assign(
            {
                icon: "info",
                title: "Notice",
                text: ""
            },
            options || {}
        );

        if (window.Swal && typeof window.Swal.fire === "function") {
            return window.Swal.fire({
                icon: payload.icon,
                title: payload.title,
                text: payload.text,
                confirmButtonColor: "#38bdf8",
                customClass: {
                    popup: "soc-swal-popup"
                }
            });
        }

        window.alert(`${payload.title}\n${payload.text}`.trim());
        return Promise.resolve();
    };

    window.socToast = function socToast(options) {
        const payload = Object.assign(
            {
                icon: "success",
                title: "Updated"
            },
            options || {}
        );

        if (window.Swal && typeof window.Swal.fire === "function") {
            return window.Swal.fire({
                toast: true,
                position: "top-end",
                timer: 2200,
                timerProgressBar: true,
                showConfirmButton: false,
                icon: payload.icon,
                title: payload.title,
                customClass: {
                    popup: "soc-swal-popup"
                }
            });
        }

        return Promise.resolve();
    };
})();
