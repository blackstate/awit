let textarea = document.querySelector("textarea");
let submitButton = document.querySelector("#btn-submit");

textarea.addEventListener("input", checkStatus);

function checkStatus(event) {
    if (!this.value) {
        submitButton.disabled = true;
        console.log(this.value);
    }
    else
    {
        submitButton.disabled = false;
    }
        

}