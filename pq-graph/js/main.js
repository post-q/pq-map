renderNodeBrowser();
updateControls();


/* ---------------------------------------------------------
 * INITIAL CAMERA
 * --------------------------------------------------------- */

setTimeout(() => {
  Graph.zoomToFit(900, 70);

  // zoomToFit animates. Capture the resulting camera only after
  // the initial transition has settled; Reset view returns here.
  setTimeout(() => {
    initialCamera = captureCamera();
  }, 1000);
}, 1800);

