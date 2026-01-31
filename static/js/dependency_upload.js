var fileNameField = document.getElementById("file-name");
var fileInputField = document.getElementById("file-input");

fileInputField.addEventListener("change", function () {
  fileNameField.innerText = "";
  for (var i = 0; i < fileInputField.files.length; i++) {
    fileNameField.innerText += fileInputField.files[i].name + "\n";
  }
});
