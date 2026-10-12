function captureCamera() {
  const camera = Graph.camera();
  const controls = Graph.controls();

  return {
    position: {
      x: camera.position.x,
      y: camera.position.y,
      z: camera.position.z
    },
    target: {
      x: controls.target.x,
      y: controls.target.y,
      z: controls.target.z
    }
  };
}

function saveBrowsingCamera() {
  browsingCamera = captureCamera();
}

function restoreCamera(saved, duration = 700) {
  if (!saved) return;

  requestAnimationFrame(() => {
    Graph.cameraPosition(
      saved.position,
      saved.target,
      duration
    );
  });
}

const DEMO_ROTATION_SPEED = 0.21;

let demoRotating = false;
let demoLastFrame = null;
let demoSmoothedDelta = 0;
let demoAxis = { x: 0, y: 1, z: 0 };

function captureDemoAxis() {
  const e = Graph.camera().matrixWorld.elements;
  const len = Math.hypot(e[4], e[5], e[6]) || 1;
  demoAxis = { x: e[4] / len, y: e[5] / len, z: e[6] / len };
}

function orbitAroundVertical(delta) {
  const camera = Graph.camera();
  const target = Graph.controls().target;

  const px = camera.position.x - target.x;
  const py = camera.position.y - target.y;
  const pz = camera.position.z - target.z;

  const angle = DEMO_ROTATION_SPEED * delta;
  const cos = Math.cos(angle);
  const sin = Math.sin(angle);
  const dot = demoAxis.x * px + demoAxis.y * py + demoAxis.z * pz;

  const crossX = demoAxis.y * pz - demoAxis.z * py;
  const crossY = demoAxis.z * px - demoAxis.x * pz;
  const crossZ = demoAxis.x * py - demoAxis.y * px;

  camera.position.set(
    target.x + px * cos + crossX * sin + demoAxis.x * dot * (1 - cos),
    target.y + py * cos + crossY * sin + demoAxis.y * dot * (1 - cos),
    target.z + pz * cos + crossZ * sin + demoAxis.z * dot * (1 - cos)
  );
  camera.lookAt(target);
}

function demoFrame(now) {
  if (!demoRotating) return;

  if (demoLastFrame !== null) {
    const delta = (now - demoLastFrame) / 1000;
    demoSmoothedDelta = demoSmoothedDelta * 0.8 + Math.min(delta, 0.25) * 0.2;
    orbitAroundVertical(DEMO_ROTATION_SPEED * Math.min(demoSmoothedDelta, 0.1));
  }

  demoLastFrame = now;
  requestAnimationFrame(demoFrame);
}

function startDemo() {
  if (demoRotating) return;

  demoRotating = true;
  demoLastFrame = null;
  demoSmoothedDelta = 1 / 60;
  captureDemoAxis();
  Graph.controls().noRotate = true;
  requestAnimationFrame(demoFrame);
}

function stopDemo() {
  if (!demoRotating) return;

  demoRotating = false;
  Graph.controls().noRotate = false;
}

document.getElementById("graph").addEventListener("pointerdown", stopDemo);

