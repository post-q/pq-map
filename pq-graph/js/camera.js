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

const DEMO_ROTATION_SPEED = 0.12;

const demoAxis = (vector => {
  const length = Math.hypot(vector.x, vector.y, vector.z);
  return {
    x: vector.x / length,
    y: vector.y / length,
    z: vector.z / length
  };
})({ x: 0.25, y: 1, z: 0.15 });

let demoRotating = false;
let demoLastFrame = null;

function rotateCamera(delta) {
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

  const delta = demoLastFrame === null
    ? 0
    : Math.min((now - demoLastFrame) / 1000, 0.05);

  demoLastFrame = now;
  rotateCamera(delta);
  requestAnimationFrame(demoFrame);
}

function startDemo() {
  if (demoRotating) return;

  demoRotating = true;
  demoLastFrame = null;
  requestAnimationFrame(demoFrame);
}

function stopDemo() {
  demoRotating = false;
}

document.getElementById("graph").addEventListener("pointerdown", stopDemo);

