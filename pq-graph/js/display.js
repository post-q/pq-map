function relationForPerspective(relation, outgoing) {
  if (outgoing) {
    return displayRelation(relation);
  }

  switch (relation) {
    case "issued_by":
      return "issues";

    case "presents_certificate":
      return "presented by";

    case "certificate_for":
      return "certificate used by";

    case "negotiated_kx":
      return "negotiated by";

    case "symmetric_cipher":
      return "used by";

    case "exposes":
      return "exposed by";

    case "cert_key":
      return "key of";

    case "cert_signature":
      return "signature of";

    default:
      return displayRelation(relation);
  }
}

function displayRelation(relation) {
  switch (relation) {
    case "presents_certificate":
      return "presents certificate";

    case "certificate_for":
      return "certificate used by";

    case "negotiated_kx":
      return "negotiated by";

    case "symmetric_cipher":
      return "symmetric cipher";

    case "issued_by":
      return "issues";

    case "cert_key":
      return "certificate key";

    case "cert_signature":
      return "certificate signature";

    case "exposes":
      return "exposes";

    default:
      return relation;
  }
}

function displayLabel(node) {

  switch (role(node)) {

    case "host":
      return node._aggregate
        ? `HOST GROUP · ${node.label}`
        : `HOST · ${node.label}`;

    case "certificate":
      return node._aggregate
        ? `CERT GROUP · ${node.label}`
        : `CERT · ${node.label}`;

    case "root_ca":
      return `ROOT CA · ${node.label}`;

    case "intermediate_ca":
      return `CA · ${node.label}`;

    default:
      return node.label || node.id;
  }
}


/* ---------------------------------------------------------
 * SEMANTIC POSITION
 * --------------------------------------------------------- */

function targetX(node) {

  switch (role(node)) {

    case "root_ca":
      return -350;

    case "intermediate_ca":
      return -230;

    case "certificate_key":
    case "certificate_signature":
      return -230;

    case "certificate":
      return -110;

    case "host":
      return 0;

    case "key_exchange":
    case "symmetric":
    case "service":
      return 150;

    default:
      return 0;
  }
}


function targetZ(node) {

  switch (role(node)) {

    case "root_ca":
      return 110;

    case "intermediate_ca":
      return 75;

    case "certificate_key":
      return 0;

    case "certificate_signature":
      return -90;

    case "certificate":
      return 0;

    case "host":
      return 0;

    case "key_exchange":
      return 75;

    case "symmetric":
      return -25;

    case "service":
      return -125;

    default:
      return 0;
  }
}


/* ---------------------------------------------------------
 * INITIAL POSITIONS
 * --------------------------------------------------------- */

const roleCounters = {};

for (const node of data.nodes) {

  const r = role(node);

  const i = roleCounters[r] || 0;
  roleCounters[r] = i + 1;

  const level =
    i === 0
      ? 0
      : Math.ceil(i / 2) * (i % 2 ? 1 : -1);

  let spacing = 24;

  if (r === "host") {
    spacing = 5;
  }

  if (r === "certificate") {
    spacing = 6;
  }

  node.x = targetX(node);
  node.y = level * spacing;
  node.z = targetZ(node);

  if (r === "host") {
    node.z += ((i % 7) - 3) * 7;
  }

  if (r === "certificate") {
    node.z += ((i % 5) - 2) * 8;
  }
}


