import { useState, useEffect, useRef, useCallback, useReducer } from "react";

const MONO = "'JetBrains Mono','Fira Code',monospace";

const WALLET_DATA = [
  {
    id: "so1",
    name: "Sub-Org 1",
    address: "0x1a2B...3c4D",
    rootUser: "usr_root_01",
    chain: "Ethereum",
    balance: "4.21 ETH",
  },
  {
    id: "so2",
    name: "Sub-Org 2",
    address: "0x5e6F...7g8H",
    rootUser: "usr_root_02",
    chain: "Ethereum",
    balance: "12,400 USDC",
  },
  {
    id: "so3",
    name: "Sub-Org 3",
    address: "GkP7...xV9m",
    rootUser: "usr_root_03",
    chain: "Solana",
    balance: "89.3 SOL",
  },
  {
    id: "so4",
    name: "Sub-Org 4",
    address: "bc1q...w8z2",
    rootUser: "usr_root_04",
    chain: "Bitcoin",
    balance: "0.045 BTC",
  },
];

const SUBORG_USER_WALLETS = {
  so1: [
    {
      id: "so1-root-wallet",
      role: "ROOT",
      short: "ROOT",
      label: "Root signer",
      userId: "usr_root_01",
      walletId: "w_so1_root",
      privateKeyId: "pk_so1_root_01",
      walletAddress: "0x1111111111111111111111111111111111110111",
      balance: "2.18 ETH",
      access: "Root",
      auth: "Passkey",
      approvers: ["usr_root_01"],
      credentials: ["CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
    {
      id: "so1-api-wallet",
      role: "API",
      short: "API",
      label: "API robot",
      userId: "usr_api_so1_01",
      walletId: "w_so1_api",
      privateKeyId: "pk_so1_api_01",
      walletAddress: "0x1111111111111111111111111111111111110222",
      balance: "1.03 ETH",
      access: "Delegated",
      auth: "API key",
      approvers: [],
      credentials: ["CREDENTIAL_TYPE_API_KEY"],
    },
    {
      id: "so1-oauth-wallet",
      role: "OAUTH",
      short: "OAUTH",
      label: "OAuth user",
      userId: "usr_oauth_so1_01",
      walletId: "w_so1_oauth",
      privateKeyId: "pk_so1_oauth_01",
      walletAddress: "0x1111111111111111111111111111111111110333",
      balance: "1.00 ETH",
      access: "OAuth",
      auth: "OAuth + passkey",
      approvers: ["usr_oauth_so1_01"],
      credentials: ["CREDENTIAL_TYPE_OAUTH", "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
  ],
  so2: [
    {
      id: "so2-root-wallet",
      role: "ROOT",
      short: "ROOT",
      label: "Root signer",
      userId: "usr_root_02",
      walletId: "w_so2_root",
      privateKeyId: "pk_so2_root_01",
      walletAddress: "0x2222222222222222222222222222222222220111",
      balance: "8,700 USDC",
      access: "Root",
      auth: "Passkey",
      approvers: ["usr_root_02"],
      credentials: ["CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
    {
      id: "so2-api-wallet",
      role: "API",
      short: "API",
      label: "API robot",
      userId: "usr_api_so2_01",
      walletId: "w_so2_api",
      privateKeyId: "pk_so2_api_01",
      walletAddress: "0x2222222222222222222222222222222222220222",
      balance: "2,200 USDC",
      access: "Delegated",
      auth: "API key",
      approvers: [],
      credentials: ["CREDENTIAL_TYPE_API_KEY"],
    },
    {
      id: "so2-oauth-wallet",
      role: "OAUTH",
      short: "OAUTH",
      label: "OAuth user",
      userId: "usr_oauth_so2_01",
      walletId: "w_so2_oauth",
      privateKeyId: "pk_so2_oauth_01",
      walletAddress: "0x2222222222222222222222222222222222220333",
      balance: "1,500 USDC",
      access: "OAuth",
      auth: "OAuth + passkey",
      approvers: ["usr_oauth_so2_01"],
      credentials: ["CREDENTIAL_TYPE_OAUTH", "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
  ],
  so3: [
    {
      id: "so3-root-wallet",
      role: "ROOT",
      short: "ROOT",
      label: "Root signer",
      userId: "usr_root_03",
      walletId: "w_so3_root",
      privateKeyId: "pk_so3_root_01",
      walletAddress: "7Sx6M7MSt9xjT9T8zMTU4nJ3FfQ2DRD1x7yYhDmmn3J2",
      balance: "51.4 SOL",
      access: "Root",
      auth: "Passkey",
      approvers: ["usr_root_03"],
      credentials: ["CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
    {
      id: "so3-api-wallet",
      role: "API",
      short: "API",
      label: "API robot",
      userId: "usr_api_so3_01",
      walletId: "w_so3_api",
      privateKeyId: "pk_so3_api_01",
      walletAddress: "5WwN8dfv2PAQm8V9pE7Rk9Q3E7N7D3g3u9v2BfXk6jD4",
      balance: "22.0 SOL",
      access: "Delegated",
      auth: "API key",
      approvers: [],
      credentials: ["CREDENTIAL_TYPE_API_KEY"],
    },
    {
      id: "so3-oauth-wallet",
      role: "OAUTH",
      short: "OAUTH",
      label: "OAuth user",
      userId: "usr_oauth_so3_01",
      walletId: "w_so3_oauth",
      privateKeyId: "pk_so3_oauth_01",
      walletAddress: "9Gv7n2C1p1F7wQ9Nf6Z6R9Zk5f8Qw4s9vD5m6sQw8W2p",
      balance: "15.9 SOL",
      access: "OAuth",
      auth: "OAuth + passkey",
      approvers: ["usr_oauth_so3_01"],
      credentials: ["CREDENTIAL_TYPE_OAUTH", "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
  ],
  so4: [
    {
      id: "so4-root-wallet",
      role: "ROOT",
      short: "ROOT",
      label: "Root signer",
      userId: "usr_root_04",
      walletId: "w_so4_root",
      privateKeyId: "pk_so4_root_01",
      walletAddress: "bc1q3p8d2n4u6k9r0w1x2y3z4a5b6c7d8e9f0g1h2j",
      balance: "0.024 BTC",
      access: "Root",
      auth: "Passkey",
      approvers: ["usr_root_04"],
      credentials: ["CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
    {
      id: "so4-api-wallet",
      role: "API",
      short: "API",
      label: "API robot",
      userId: "usr_api_so4_01",
      walletId: "w_so4_api",
      privateKeyId: "pk_so4_api_01",
      walletAddress: "bc1q7n0k4h5f8g2d3s4a6w7z8x9c0v1b2n3m4q5w6e",
      balance: "0.011 BTC",
      access: "Delegated",
      auth: "API key",
      approvers: [],
      credentials: ["CREDENTIAL_TYPE_API_KEY"],
    },
    {
      id: "so4-oauth-wallet",
      role: "OAUTH",
      short: "OAUTH",
      label: "OAuth user",
      userId: "usr_oauth_so4_01",
      walletId: "w_so4_oauth",
      privateKeyId: "pk_so4_oauth_01",
      walletAddress: "bc1q4v5b6n7m8q9w0e1r2t3y4u5i6o7p8a9s0d1f2g",
      balance: "0.010 BTC",
      access: "OAuth",
      auth: "OAuth + passkey",
      approvers: ["usr_oauth_so4_01"],
      credentials: ["CREDENTIAL_TYPE_OAUTH", "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"],
    },
  ],
};

const ACTOR_COLORS = {
  ROOT: "#fbbf24",
  API: "#38bdf8",
  OAUTH: "#a78bfa",
};

const ACTION_FORM_CONFIG = {
  SIGN: {
    showDestination: true,
    showAmount: true,
    showResource: false,
    showTargetId: false,
  },
  CREATE: {
    showDestination: false,
    showAmount: false,
    showResource: true,
    showTargetId: true,
  },
  UPDATE: {
    showDestination: false,
    showAmount: false,
    showResource: true,
    showTargetId: true,
  },
  DELETE: {
    showDestination: false,
    showAmount: false,
    showResource: true,
    showTargetId: true,
  },
  EXPORT: {
    showDestination: false,
    showAmount: false,
    showResource: true,
    showTargetId: true,
  },
  IMPORT: {
    showDestination: false,
    showAmount: false,
    showResource: true,
    showTargetId: true,
  },
};

const RESOURCE_OPTIONS = ["WALLET", "USER", "PRIVATE_KEY", "POLICY", "ORGANIZATION"];
const NON_SIGN_RESOURCE_PRESETS = ["WALLET", "USER", "POLICY"];
const AMOUNT_UNIT_BY_CHAIN = {
  Ethereum: "wei",
  Solana: "lamports",
  Bitcoin: "sats",
  Tron: "sun",
};

function getActorsForSubOrg(subOrgId) {
  return SUBORG_USER_WALLETS[subOrgId] || [];
}

function getDefaultActorId(subOrgId) {
  return getActorsForSubOrg(subOrgId)[0]?.id || null;
}

function shortenAddress(address) {
  if (!address) return "N/A";
  if (address.length <= 14) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function getViewportWidth() {
  if (typeof window === "undefined") return 1440;
  if (window.visualViewport?.width) return window.visualViewport.width;
  return window.innerWidth;
}

function getSelectedTemplateContext(selW, selActorId) {
  if (!selW) return null;
  const actors = getActorsForSubOrg(selW.id);
  const actor = actors.find((a) => a.id === selActorId) || actors[0];
  if (!actor) return null;

  return {
    subOrgId: selW.id,
    subOrgName: selW.name,
    chain: selW.chain,
    actorId: actor.id,
    actorRole: actor.role,
    actorShort: actor.short,
    userId: actor.userId,
    walletId: actor.walletId,
    walletAddress: actor.walletAddress,
    privateKeyId: actor.privateKeyId,
  };
}

function resolveTemplateString(input, context) {
  if (typeof input !== "string" || !input || !context) return input;
  const tokenMap = {
    "<USER_ID>": context.userId,
    "<DA_USER>": context.userId,
    "<WALLET_ID>": context.walletId,
    "<ADDR>": context.walletAddress,
    "<PK_ID>": context.privateKeyId,
  };

  let output = input;
  Object.entries(tokenMap).forEach(([token, value]) => {
    if (value) output = output.split(token).join(value);
  });

  if (context.chain === "Bitcoin" && context.walletAddress) {
    output = output.split("<BTC_ADDR>").join(context.walletAddress);
  }

  return output;
}

function resolveExamplePolicy(policy, context) {
  if (!policy) return policy;
  if (!context) return { ...policy };
  return {
    ...policy,
    policyName: resolveTemplateString(policy.policyName, context),
    condition: resolveTemplateString(policy.condition, context),
    consensus: resolveTemplateString(policy.consensus, context),
  };
}

const CATS = [
  {
    name: "Access Control",
    examples: [
      {
        label: "Allow user to create wallets",
        policy: {
          policyName: "Allow user to create wallets",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition: "activity.resource == 'WALLET' && activity.action == 'CREATE'",
        },
      },
      {
        label: "Allow users with tag to create users",
        policy: {
          policyName: "Allow user_tag to create users",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.tags.contains('<USER_TAG_ID>'))",
          condition: "activity.resource == 'USER' && activity.action == 'CREATE'",
        },
      },
      {
        label: "Deny delete for tagged users",
        policy: {
          policyName: "Deny tagged users from deleting",
          effect: "EFFECT_DENY",
          consensus: "approvers.any(user, user.tags.contains('<USER_TAG_ID>'))",
          condition: "activity.action == 'DELETE'",
        },
      },
      {
        label: "2-of-N tag approval for policy creation",
        policy: {
          policyName: "Require two tagged users to create policies",
          effect: "EFFECT_ALLOW",
          consensus:
            "approvers.filter(user, user.tags.contains('<USER_TAG_ID>')).count() >= 2",
          condition: "activity.resource == 'POLICY' && activity.action == 'CREATE'",
        },
      },
      {
        label: "Allow signing with passkeys only",
        policy: {
          policyName: "Allow signing with only passkeys",
          effect: "EFFECT_ALLOW",
          consensus:
            "credentials.any(credential, credential.type == 'CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR')",
          condition: "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2'",
        },
      },
    ],
  },
  {
    name: "Signing Control",
    examples: [
      {
        label: "Sign with specific wallet",
        policy: {
          policyName: "Allow sign with wallet",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition: "activity.action == 'SIGN' && wallet.id == '<WALLET_ID>'",
        },
      },
      {
        label: "Sign with wallet account address",
        policy: {
          policyName: "Allow sign with account",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition: "activity.action == 'SIGN' && wallet_account.address == '<ADDR>'",
        },
      },
      {
        label: "Sign with private key",
        policy: {
          policyName: "Allow sign with private key",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition: "activity.action == 'SIGN' && private_key.id == '<PK_ID>'",
        },
      },
    ],
  },
  {
    name: "Ethereum",
    examples: [
      {
        label: "Allow ETH to Uniswap V2",
        policy: {
          policyName: "Allow ETH to Uniswap V2",
          effect: "EFFECT_ALLOW",
          condition: "eth.tx.to == '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'",
          consensus: "",
        },
      },
      {
        label: "Allow USDC transfers only",
        policy: {
          policyName: "Allow USDC only",
          effect: "EFFECT_ALLOW",
          condition: "eth.tx.to == '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'",
          consensus: "",
        },
      },
      {
        label: "Allow Sepolia testnet",
        policy: {
          policyName: "Allow Sepolia",
          effect: "EFFECT_ALLOW",
          condition: "eth.tx.chain_id == 11155111",
          consensus: "",
        },
      },
      {
        label: "Limit WETH amount + destination",
        policy: {
          policyName: "Limit WETH",
          effect: "EFFECT_ALLOW",
          condition:
            "eth.tx.contract_call_args['wad'] < 1000000000000000000 && eth.tx.contract_call_args['dst'] == '0x08d2b0a37F869FF76BACB5Bab3278E26ab7067B7'",
          consensus: "",
        },
      },
      {
        label: "Enforce transfer function sig",
        policy: {
          policyName: "Allow only transfer",
          effect: "EFFECT_ALLOW",
          condition:
            "eth.tx.function_name == 'transfer' && eth.tx.function_signature == '0xa9059cbb'",
          consensus: "",
        },
      },
      {
        label: "Allow Aave Pool + USDC",
        policy: {
          policyName: "Allow Aave+USDC",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition:
            "eth.tx.to in ['0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48','0x794a61358D6845594F94dc1DB02A252b5b4814aD']",
        },
      },
      {
        label: "Allow EIP-7702 auth signing",
        policy: {
          policyName: "Allow EIP-7702",
          effect: "EFFECT_ALLOW",
          condition:
            "eth.eip_7702_authorization.address == '<ADDR>' && activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2'",
          consensus: "",
        },
      },
    ],
  },
  {
    name: "Solana",
    examples: [
      {
        label: "SPL transfer below threshold",
        policy: {
          policyName: "Allow SPL < threshold",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition:
            "solana.tx.instructions.count() == 1 && solana.tx.spl_transfers.all(transfer, transfer.amount < <AMOUNT>)",
        },
      },
      {
        label: "SPL transfers of specific mint",
        policy: {
          policyName: "Allow SPL mint",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<USER_ID>')",
          condition:
            "solana.tx.spl_transfers.all(transfer, transfer.token_mint == '<MINT>')",
        },
      },
      {
        label: "Allow Jupiter swap",
        policy: {
          policyName: "Allow Jupiter route",
          effect: "EFFECT_ALLOW",
          condition:
            "solana.tx.instructions.any(i, i.program_key == 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4')",
          consensus: "",
        },
      },
    ],
  },
  {
    name: "Bitcoin",
    examples: [
      {
        label: "BTC to specific address",
        policy: {
          policyName: "Allow BTC to addr",
          effect: "EFFECT_ALLOW",
          condition: "bitcoin.tx.outputs.all(o, o.address == '<BTC_ADDR>')",
          consensus: "",
        },
      },
      {
        label: "Restrict outputs <200k sats",
        policy: {
          policyName: "BTC <200k sats",
          effect: "EFFECT_ALLOW",
          condition: "bitcoin.tx.outputs.all(o, o.value < 200000)",
          consensus: "",
        },
      },
    ],
  },
  {
    name: "Tron",
    examples: [
      {
        label: "TRX transfers under 10 TRX",
        policy: {
          policyName: "TRX <10",
          effect: "EFFECT_ALLOW",
          condition: "tron.tx.contract[0].amount < 10000000",
          consensus: "",
        },
      },
    ],
  },
  {
    name: "Consensus",
    examples: [
      {
        label: "Admin gate high-value (>1 ETH)",
        policy: {
          policyName: "Admin gate >1ETH",
          effect: "EFFECT_ALLOW",
          condition: "eth.tx.value > '1000000000000000000'",
          consensus: "approvers.any(user, user.id == 'usr_admin_01')",
        },
      },
      {
        label: "Delegated user scoped to address",
        policy: {
          policyName: "Delegated scoped",
          effect: "EFFECT_ALLOW",
          consensus: "approvers.any(user, user.id == '<DA_USER>')",
          condition: "eth.tx.to == '<ADDR>'",
        },
      },
    ],
  },
  {
    name: "Emergency",
    examples: [
      {
        label: "Emergency freeze all",
        policy: {
          policyName: "emergency-freeze-all",
          effect: "EFFECT_DENY",
          condition: "",
          consensus: "",
        },
      },
      {
        label: "Deny all wallet exports",
        policy: {
          policyName: "Deny exports",
          effect: "EFFECT_DENY",
          condition: "activity.resource == 'WALLET' && activity.action == 'EXPORT'",
          consensus: "",
        },
      },
    ],
  },
];

const LANG_REF = {
  condKw: {
    "activity.resource": "USER,PRIVATE_KEY,POLICY,WALLET,ORGANIZATION,AUTH,OTP",
    "activity.action": "CREATE,UPDATE,DELETE,SIGN,EXPORT,IMPORT",
    "eth.tx.to": "address",
    "eth.tx.value": "wei",
    "eth.tx.contract_call_args": "map",
    "solana.tx": "object",
    "bitcoin.tx": "object",
    "tron.tx": "object",
    "wallet.id": "string",
    "wallet_account.address": "string",
    "private_key.id": "string",
    "private_key.tags": "list",
  },
  consKw: { approvers: "users who approved", credentials: "auth credentials" },
  ops: "== != < > <= >= && || in",
  listFn: ".all() .any() .contains() .count() .filter()",
};

function parsePolicy(p) {
  const c = p.condition || "";
  const s = p.consensus || "";

  const r = {
    effect: p.effect || "",
    isAllow: p.effect === "EFFECT_ALLOW",
    isDeny: p.effect === "EFFECT_DENY",
    hasCond: !!c.trim(),
    hasCons: !!s.trim(),
    targetAddr: null,
    targetLabel: null,
    resrc: null,
    action: null,
    isGlobalDeny: false,
    isHighVal: false,
    needsApproval: false,
    approvalN: 1,
    condSum: "",
    consSum: "",
    chain: null,
  };

  if (r.isDeny && !r.hasCond) r.isGlobalDeny = true;

  const am = c.match(/eth\.tx\.to\s*==\s*'(0x[a-fA-F0-9.]+)'/);
  if (am) {
    r.targetAddr = am[1];
    r.targetLabel = am[1].startsWith("0x7a25")
      ? "Uniswap V2"
      : am[1].startsWith("0xA0b8")
        ? "USDC"
        : am[1].startsWith("0x794a")
          ? "Aave"
          : am[1].startsWith("0x08d2")
            ? "WETH Dst"
            : am[1].slice(0, 6) + "..." + am[1].slice(-4);
  }

  if (c.match(/eth\.tx\.to\s+in\s+\[/)) {
    r.targetLabel = "Multi-contract";
    r.targetAddr = "multi";
  }

  const rm = c.match(/activity\.resource\s*==\s*'(\w+)'/);
  if (rm) r.resrc = rm[1];

  const acm = c.match(/activity\.action\s*==\s*'(\w+)'/);
  if (acm) r.action = acm[1];

  if (c.includes("eth.tx.value") && (c.includes(">") || c.includes(">="))) r.isHighVal = true;

  if (s.includes("approvers") || s.includes("credentials")) {
    r.needsApproval = true;
    const cm = s.match(/\.count\(\)\s*>=\s*(\d+)/);
    if (cm) r.approvalN = parseInt(cm[1], 10);
  }

  if (c.includes("eth.tx") || c.includes("eth.eip")) r.chain = "Ethereum";
  else if (c.includes("solana.tx")) r.chain = "Solana";
  else if (c.includes("bitcoin.tx")) r.chain = "Bitcoin";
  else if (c.includes("tron.tx")) r.chain = "Tron";

  const pts = [];
  if (r.resrc) pts.push(r.resrc);
  if (r.action) pts.push(r.action);
  if (r.targetLabel) pts.push(r.targetLabel);
  if (r.isHighVal) pts.push("High-val");
  if (r.chain) pts.push(r.chain);

  r.condSum = pts.join(" · ") || (r.hasCond ? "Custom" : "All activities");
  if (r.needsApproval) r.consSum = r.approvalN > 1 ? `${r.approvalN}-of-N approval` : "Admin approval";

  return r;
}

function evaluateConsensus(consensus, tx) {
  const s = (consensus || "").trim();
  if (!s) return { status: "PASS", why: "No consensus required" };

  const approverMatch = s.match(/approvers\.any\(user,\s*user\.id\s*==\s*'([^']+)'\)/);
  if (approverMatch) {
    const neededApprover = approverMatch[1];
    const hasApprover = (tx.approvers || []).includes(neededApprover);
    return hasApprover
      ? { status: "PASS", why: `Approver ${neededApprover} present` }
      : { status: "PENDING", why: `Waiting for approver ${neededApprover}` };
  }

  const countMatch = s.match(/\.count\(\)\s*>=\s*(\d+)/);
  if (countMatch) {
    const neededCount = parseInt(countMatch[1], 10);
    const currentCount = (tx.approvers || []).length;
    return currentCount >= neededCount
      ? { status: "PASS", why: `${currentCount}-of-${neededCount} approvers present` }
      : { status: "PENDING", why: `Need ${neededCount} approvers (${currentCount} present)` };
  }

  const credentialMatch = s.match(/credentials\.any\(credential,\s*credential\.type\s*==\s*'([^']+)'\)/);
  if (credentialMatch) {
    const requiredCredential = credentialMatch[1];
    const hasCredential = (tx.credentials || []).includes(requiredCredential);
    return hasCredential
      ? { status: "PASS", why: `Credential ${requiredCredential} present` }
      : { status: "DENY", why: `Missing credential ${requiredCredential}` };
  }

  if (s.includes("approvers")) return { status: "PENDING", why: "Consensus approver check required" };
  if (s.includes("credentials")) return { status: "DENY", why: "Credential policy not satisfied" };
  return { status: "PENDING", why: "Consensus expression unresolved in demo parser" };
}

function simulateTransaction(policies, tx) {
  const steps = [];

  if (!policies.length) {
    steps.push({ pol: null, res: "DENY", why: "No policies -> implicit deny" });
    return { steps, final: "DENIED" };
  }

  let hasDeny = false;
  let hasAllow = false;
  let hasSatisfiedAllow = false;
  let hasPendingAllow = false;

  policies.forEach((p) => {
    const pp = parsePolicy(p);
    let m = true;
    let why = "Matched";
    const c = p.condition || "";

    if (pp.hasCond) {
      const am2 = c.match(/eth\.tx\.to\s*==\s*'([^']+)'/);
      if (am2 && tx.to && am2[1] !== tx.to) {
        m = false;
        why = `To != ${am2[1].slice(0, 10)}...`;
      }

      const im = c.match(/eth\.tx\.to\s+in\s+\[([^\]]+)\]/);
      if (im && tx.to && !im[1].includes(tx.to)) {
        m = false;
        why = "Not in allowlist";
      }

      if (c.includes("eth.tx.value") && tx.value) {
        const vm = c.match(/eth\.tx\.value\s*>\s*'(\d+)'/);
        if (vm) {
          try {
            if (BigInt(tx.value) <= BigInt(vm[1])) {
              m = false;
              why = "Below threshold";
            }
          } catch (e) {
            // no-op for malformed demo value
          }
        }
      }

      if (c.includes("solana.tx") && tx.chain !== "Solana") {
        m = false;
        why = "Wrong chain";
      }

      if (c.includes("bitcoin.tx") && tx.chain !== "Bitcoin") {
        m = false;
        why = "Wrong chain";
      }

      if (c.includes("tron.tx") && tx.chain !== "Tron") {
        m = false;
        why = "Wrong chain";
      }

      if (c.includes("activity.resource") && tx.resource) {
        const rm2 = c.match(/activity\.resource\s*==\s*'(\w+)'/);
        if (rm2 && rm2[1] !== tx.resource) {
          m = false;
          why = "Resource mismatch";
        }
      }

      if (c.includes("activity.action") && tx.action) {
        const am3 = c.match(/activity\.action\s*==\s*'(\w+)'/);
        if (am3 && am3[1] !== tx.action) {
          m = false;
          why = "Action mismatch";
        }
      }

      if (c.includes("activity.type") && tx.activityType) {
        const atm = c.match(/activity\.type\s*==\s*'([^']+)'/);
        if (atm && atm[1] !== tx.activityType) {
          m = false;
          why = "Activity type mismatch";
        }
      }

      if (c.includes("wallet.id") && tx.walletId) {
        const wim = c.match(/wallet\.id\s*==\s*'([^']+)'/);
        if (wim && wim[1] !== tx.walletId) {
          m = false;
          why = "Wallet mismatch";
        }
      }

      if (c.includes("wallet_account.address") && tx.walletAddress) {
        const wam = c.match(/wallet_account\.address\s*==\s*'([^']+)'/);
        if (wam && wam[1].toLowerCase() !== tx.walletAddress.toLowerCase()) {
          m = false;
          why = "Account address mismatch";
        }
      }

      if (c.includes("private_key.id") && tx.privateKeyId) {
        const pkm = c.match(/private_key\.id\s*==\s*'([^']+)'/);
        if (pkm && pkm[1] !== tx.privateKeyId) {
          m = false;
          why = "Private key mismatch";
        }
      }
    }

    if (!m) {
      steps.push({ pol: p.policyName, res: "SKIP", why, eff: p.effect });
      return;
    }

    if (pp.isDeny) {
      hasDeny = true;
      steps.push({ pol: p.policyName, res: "DENY", why: "DENY match", eff: p.effect });
      return;
    }

    if (pp.isAllow) {
      hasAllow = true;
      if (!pp.needsApproval) {
        hasSatisfiedAllow = true;
        steps.push({ pol: p.policyName, res: "ALLOW", why: "ALLOW match", eff: p.effect });
        return;
      }

      const consensusEval = evaluateConsensus(p.consensus, tx);
      if (consensusEval.status === "PASS") {
        hasSatisfiedAllow = true;
        steps.push({ pol: p.policyName, res: "ALLOW", why: consensusEval.why, eff: p.effect });
      } else if (consensusEval.status === "PENDING") {
        hasPendingAllow = true;
        steps.push({ pol: p.policyName, res: "PENDING", why: consensusEval.why, eff: p.effect });
      } else {
        steps.push({ pol: p.policyName, res: "SKIP", why: consensusEval.why, eff: p.effect });
      }
    }
  });

  if (hasDeny && (hasSatisfiedAllow || hasPendingAllow || hasAllow)) {
    steps.push({ pol: null, res: "OVERRIDE", why: "DENY overrides ALLOW", eff: "EFFECT_DENY" });
  }

  return {
    steps,
    final: hasDeny ? "DENIED" : hasSatisfiedAllow ? "ALLOWED" : hasPendingAllow ? "PENDING" : "DENIED",
  };
}

function policiesReducer(s, a) {
  switch (a.type) {
    case "ADD":
      return [...s, { ...a.policy, _id: Date.now() + Math.random() }];
    case "REMOVE":
      return s.filter((p) => p._id !== a.id);
    case "CLEAR":
      return [];
    default:
      return s;
  }
}

const inputSt = {
  width: "100%",
  padding: "7px 9px",
  background: "#0f0f2a",
  border: "1px solid rgba(99,102,241,0.2)",
  borderRadius: "4px",
  color: "#e2e8f0",
  fontFamily: MONO,
  fontSize: "11px",
  outline: "none",
  boxSizing: "border-box",
};

const lblSt = {
  fontSize: "10px",
  color: "#6366f1",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  marginBottom: "4px",
  fontWeight: 600,
};

const pill = (on) => ({
  padding: "3px 7px",
  fontSize: "9px",
  fontFamily: MONO,
  border: on ? "1px solid rgba(99,102,241,0.5)" : "1px solid rgba(99,102,241,0.12)",
  borderRadius: "3px",
  background: on ? "rgba(99,102,241,0.15)" : "transparent",
  color: on ? "#a5b4fc" : "#64748b",
  cursor: "pointer",
  fontWeight: on ? 600 : 400,
});

function WalletDetailPanel({ wallet, policies, actorId, onSelectActor, onClose, onEvalResult }) {
  const [simTo, setSimTo] = useState("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D");
  const [simVal, setSimVal] = useState("500000000000000000");
  const [simAct, setSimAct] = useState("SIGN");
  const [simResource, setSimResource] = useState("WALLET");
  const [simTargetId, setSimTargetId] = useState("");
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const actors = getActorsForSubOrg(wallet.id);
  const activeActor = actors.find((a) => a.id === actorId) || actors[0] || null;
  const actionCfg = ACTION_FORM_CONFIG[simAct] || ACTION_FORM_CONFIG.SIGN;
  const amountUnit = AMOUNT_UNIT_BY_CHAIN[wallet.chain] || "units";

  useEffect(() => {
    setResult(null);
  }, [policies, wallet.id, actorId]);

  useEffect(() => {
    if (!activeActor && actors[0]) {
      onSelectActor(actors[0].id);
    }
  }, [activeActor, actors, onSelectActor]);

  const relevant = policies
    .map((p) => ({ ...p, ...parsePolicy(p) }))
    .filter((p) => {
      if (p.isGlobalDeny || !p.hasCond) return true;
      if (!p.chain || p.chain === wallet.chain) return true;
      return false;
    });

  const run = () => {
    setRunning(true);
    setResult(null);
    setTimeout(() => {
      const txPayload = {
        to: actionCfg.showDestination ? simTo : "",
        value: actionCfg.showAmount ? simVal : "0",
        chain: wallet.chain,
        resource: actionCfg.showResource ? simResource : "WALLET",
        action: simAct,
        activityType: simAct === "SIGN" ? "ACTIVITY_TYPE_SIGN_TRANSACTION_V2" : undefined,
        walletId: activeActor?.walletId || "",
        walletAddress: activeActor?.walletAddress || "",
        privateKeyId: activeActor?.privateKeyId || "",
        targetId: simTargetId,
        approvers: activeActor?.approvers || [],
        credentials: activeActor?.credentials || [],
      };
      const evalResult = simulateTransaction(policies, txPayload);
      setResult(evalResult);
      if (typeof onEvalResult === "function") {
        onEvalResult({
          walletId: wallet.id,
          actorId: activeActor?.id || null,
          tx: txPayload,
          result: evalResult,
          timestamp: Date.now(),
        });
      }
      setRunning(false);
    }, 300);
  };

  const rc = { ALLOWED: "#34d399", DENIED: "#ef4444", PENDING: "#6366f1" };
  const rl = {
    ALLOWED: "TRANSACTION ALLOWED",
    DENIED: "TRANSACTION DENIED",
    PENDING: "AWAITING APPROVAL",
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "#080820",
        borderLeft: "1px solid rgba(99,102,241,0.1)",
      }}
    >
      <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(99,102,241,0.08)", flexShrink: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ fontSize: "11px", fontWeight: 700, color: "#e2e8f0" }}>End-User Wallet View</div>
          <button
            onClick={onClose}
            style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: "14px" }}
          >
            x
          </button>
        </div>
        <div
          style={{
            padding: "10px",
            background: "rgba(99,102,241,0.06)",
            borderRadius: "6px",
            border: "1px solid rgba(99,102,241,0.12)",
          }}
        >
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#a5b4fc", marginBottom: 4 }}>{wallet.name}</div>
          {[
            ["Sub-Org", wallet.address],
            ["Chain", wallet.chain],
            ["Total Balance", wallet.balance],
            ["Root User", wallet.rootUser],
          ].map(([k, v]) => (
            <div key={k} style={{ fontSize: "9px", color: "#64748b" }}>
              <span style={{ color: "#475569" }}>{k}:</span>{" "}
              <span
                style={{
                  color: k.includes("Balance") ? "#e2e8f0" : "#94a3b8",
                  fontWeight: k.includes("Balance") ? 600 : 400,
                }}
              >
                {v}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(99,102,241,0.08)", flexShrink: 0 }}>
        <div style={lblSt}>Signer Wallets ({actors.length})</div>
        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap", marginBottom: 8 }}>
          {actors.map((a) => {
            const isOn = a.id === activeActor?.id;
            return (
              <button
                key={a.id}
                onClick={() => onSelectActor(a.id)}
                style={{
                  padding: "4px 6px",
                  fontSize: "8px",
                  fontFamily: MONO,
                  border: isOn ? `1px solid ${ACTOR_COLORS[a.role]}` : "1px solid rgba(99,102,241,0.12)",
                  borderRadius: "4px",
                  background: isOn ? `${ACTOR_COLORS[a.role]}22` : "rgba(0,0,0,0.15)",
                  color: isOn ? ACTOR_COLORS[a.role] : "#64748b",
                  fontWeight: isOn ? 700 : 500,
                  cursor: "pointer",
                }}
              >
                {a.short} · {a.label}
              </button>
            );
          })}
        </div>
        {activeActor && (
          <div
            style={{
              marginBottom: 10,
              padding: "7px 8px",
              border: `1px solid ${ACTOR_COLORS[activeActor.role]}33`,
              borderRadius: "4px",
              background: `${ACTOR_COLORS[activeActor.role]}12`,
            }}
          >
            {[
              ["User", activeActor.userId],
              ["Wallet", activeActor.walletId],
              ["Private Key", activeActor.privateKeyId],
              ["Address", shortenAddress(activeActor.walletAddress)],
              ["Access", activeActor.access],
              ["Auth", activeActor.auth],
              ["Balance", activeActor.balance],
            ].map(([k, v]) => (
              <div key={k} style={{ fontSize: "8px", color: "#94a3b8" }}>
                <span style={{ color: "#64748b" }}>{k}:</span> {v}
              </div>
            ))}
          </div>
        )}

        <div style={lblSt}>Applicable Policies ({relevant.length})</div>
        {relevant.length === 0 ? (
          <div style={{ fontSize: "10px", color: "#ef4444", padding: "6px 0" }}>No policies. Wallet fully blocked.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "3px", maxHeight: 100, overflow: "auto" }}>
            {relevant.map((p, i) => (
              <div
                key={i}
                style={{
                  padding: "5px 7px",
                  borderRadius: "3px",
                  fontSize: "9px",
                  background: p.isDeny ? "rgba(239,68,68,0.06)" : "rgba(52,211,153,0.04)",
                  borderLeft: `2px solid ${p.isDeny ? "#ef4444" : "#34d399"}`,
                }}
              >
                <span style={{ color: "#e2e8f0", fontWeight: 600 }}>{p.policyName}</span>
                <span
                  style={{
                    marginLeft: 5,
                    fontSize: "7px",
                    padding: "1px 4px",
                    borderRadius: "2px",
                    fontWeight: 700,
                    background: p.isDeny ? "rgba(239,68,68,0.12)" : "rgba(52,211,153,0.12)",
                    color: p.isDeny ? "#f87171" : "#34d399",
                  }}
                >
                  {p.effect}
                </span>
                {p.needsApproval && <span style={{ fontSize: "7px", marginLeft: 3, color: "#a5b4fc" }}>consensus</span>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ padding: "10px 14px", flex: 1, overflow: "auto" }}>
        <div style={lblSt}>Transaction Simulator</div>
        <div style={{ fontSize: "9px", color: "#475569", marginBottom: 8, lineHeight: 1.5 }}>
          Simulate a TX from {activeActor ? `${activeActor.label}` : "selected signer wallet"}. Watch the policy engine
          evaluate step-by-step.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <div>
            <div style={{ fontSize: "9px", color: "#475569", marginBottom: 2 }}>Action</div>
            <select
              style={{ ...inputSt, fontSize: "10px", padding: "5px 8px" }}
              value={simAct}
              onChange={(e) => setSimAct(e.target.value)}
            >
              {["SIGN", "CREATE", "UPDATE", "DELETE", "EXPORT", "IMPORT"].map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </div>

          {actionCfg.showDestination && (
            <div>
              <div style={{ fontSize: "9px", color: "#475569", marginBottom: 2 }}>Destination</div>
              <input
                style={{ ...inputSt, fontSize: "10px", padding: "5px 8px" }}
                value={simTo}
                onChange={(e) => setSimTo(e.target.value)}
              />
            </div>
          )}

          {actionCfg.showAmount && (
            <div>
              <div style={{ fontSize: "9px", color: "#475569", marginBottom: 2 }}>Amount ({amountUnit})</div>
              <input
                style={{ ...inputSt, fontSize: "10px", padding: "5px 8px" }}
                value={simVal}
                onChange={(e) => setSimVal(e.target.value)}
              />
            </div>
          )}

          {actionCfg.showResource && (
            <div>
              <div style={{ fontSize: "9px", color: "#475569", marginBottom: 2 }}>Resource</div>
              <select
                style={{ ...inputSt, fontSize: "10px", padding: "5px 8px" }}
                value={simResource}
                onChange={(e) => setSimResource(e.target.value)}
              >
                {RESOURCE_OPTIONS.map((res) => (
                  <option key={res}>{res}</option>
                ))}
              </select>
            </div>
          )}

          {actionCfg.showTargetId && (
            <div>
              <div style={{ fontSize: "9px", color: "#475569", marginBottom: 2 }}>Target ID (optional)</div>
              <input
                style={{ ...inputSt, fontSize: "10px", padding: "5px 8px" }}
                value={simTargetId}
                onChange={(e) => setSimTargetId(e.target.value)}
                placeholder="wallet_123 / user_123 / policy_123"
              />
            </div>
          )}

          {simAct === "SIGN" ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
              {[
                ["Uniswap 0.5E", "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "500000000000000000"],
                ["USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0"],
                ["Unknown 2E", "0xDEAD000000000000000000000000000000000000", "2000000000000000000"],
              ].map(([l, to, v]) => (
                <button
                  key={l}
                  onClick={() => {
                    setSimTo(to);
                    setSimVal(v);
                  }}
                  style={pill(false)}
                >
                  {l}
                </button>
              ))}
            </div>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
              {NON_SIGN_RESOURCE_PRESETS.map((res) => (
                <button key={res} onClick={() => setSimResource(res)} style={pill(simResource === res)}>
                  {res}
                </button>
              ))}
            </div>
          )}

          <button
            onClick={run}
            disabled={running}
            style={{
              padding: "8px",
              fontSize: "11px",
              fontFamily: MONO,
              fontWeight: 700,
              border: "none",
              borderRadius: "5px",
              background: running ? "rgba(99,102,241,0.1)" : "rgba(99,102,241,0.2)",
              color: running ? "#475569" : "#a5b4fc",
              cursor: running ? "wait" : "pointer",
            }}
          >
            {running ? "Evaluating..." : "Simulate Transaction"}
          </button>
        </div>

        {result && (
          <div style={{ marginTop: 10 }}>
            <div
              style={{
                padding: "9px 11px",
                borderRadius: "6px",
                marginBottom: 8,
                background: `${rc[result.final] || "#64748b"}12`,
                border: `1px solid ${rc[result.final] || "#64748b"}33`,
              }}
            >
              <div style={{ fontSize: "12px", fontWeight: 700, color: rc[result.final] }}>
                {result.final === "ALLOWED" ? "✅" : result.final === "DENIED" ? "⛔" : "🔐"} {rl[result.final]}
              </div>
              {result.final === "PENDING" && (
                <div style={{ fontSize: "9px", color: "#a5b4fc", marginTop: 3 }}>
                  Matches ALLOW but requires approver co-signature.
                </div>
              )}
              {result.final === "DENIED" && result.steps.some((s) => s.res === "OVERRIDE") && (
                <div style={{ fontSize: "9px", color: "#f87171", marginTop: 3 }}>
                  ALLOW matched but DENY takes precedence.
                </div>
              )}
            </div>

            <div style={lblSt}>Evaluation Steps</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
              {result.steps.map((st, i) => {
                const sc =
                  st.res === "ALLOW"
                    ? "#34d399"
                    : st.res === "DENY" || st.res === "OVERRIDE"
                      ? "#ef4444"
                      : st.res === "PENDING"
                        ? "#6366f1"
                        : "#475569";

                return (
                  <div
                    key={i}
                    style={{
                      padding: "5px 7px",
                      borderRadius: "3px",
                      fontSize: "9px",
                      fontFamily: MONO,
                      background: st.res === "OVERRIDE" ? "rgba(239,68,68,0.08)" : "rgba(0,0,0,0.2)",
                      borderLeft: `2px solid ${sc}`,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ color: "#94a3b8" }}>{st.pol || "ENGINE"}</span>
                      <span
                        style={{
                          fontSize: "7px",
                          fontWeight: 700,
                          color: sc,
                          padding: "1px 4px",
                          borderRadius: "2px",
                          background: `${sc}18`,
                        }}
                      >
                        {st.res}
                      </span>
                    </div>
                    <div style={{ color: "#64748b", fontSize: "8px", marginTop: 1 }}>{st.why}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GalaxyCanvas({ policies, selectedWallet, selectedActorId, onSelectWallet }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const timeRef = useRef(0);
  const swRef = useRef({ active: false, radius: 0, opacity: 0 });
  const prevD = useRef(false);
  const soPos = useRef([]);

  const parsed = policies.map(parsePolicy);
  const hasGD = parsed.some((p) => p.isGlobalDeny);
  const hasD = parsed.some((p) => p.isDeny);
  const hasA = parsed.some((p) => p.isAllow);
  const hasCon = parsed.some((p) => p.needsApproval);

  const uTargets = parsed
    .filter((p) => p.targetAddr)
    .filter((v, i, a) => a.findIndex((t) => t.targetAddr === v.targetAddr) === i);

  const dWins = hasD && hasA;
  const isBlk = !policies.length || (hasD && (!hasA || dWins));

  useEffect(() => {
    if (hasD && !prevD.current) swRef.current = { active: true, radius: 0, opacity: 1 };
    prevD.current = hasD;
  }, [hasD]);

  const onClick = useCallback(
    (e) => {
      const cv = canvasRef.current;
      if (!cv) return;
      const rect = cv.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      for (let i = 0; i < soPos.current.length; i += 1) {
        const s = soPos.current[i];
        const actorHit = (s.actors || []).find((a) => x >= a.x && x <= a.x + a.w && y >= a.y && y <= a.y + a.h);
        if (actorHit) {
          onSelectWallet(s.subOrg, actorHit.id);
          return;
        }

        if (Math.abs(x - s.card.x) < s.card.w / 2 + 5 && Math.abs(y - s.card.y) < s.card.h / 2 + 5) {
          onSelectWallet(s.subOrg, getDefaultActorId(s.subOrg.id));
          return;
        }
      }
    },
    [onSelectWallet],
  );

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;

    const ctx = cv.getContext("2d");
    const dpr = window.devicePixelRatio || 1;

    let w;
    let h;
    const sos = [];

    const rr = (x, y, w2, h2, r) => {
      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + w2 - r, y);
      ctx.quadraticCurveTo(x + w2, y, x + w2, y + r);
      ctx.lineTo(x + w2, y + h2 - r);
      ctx.quadraticCurveTo(x + w2, y + h2, x + w2 - r, y + h2);
      ctx.lineTo(x + r, y + h2);
      ctx.quadraticCurveTo(x, y + h2, x, y + h2 - r);
      ctx.lineTo(x, y + r);
      ctx.quadraticCurveTo(x, y, x + r, y);
      ctx.closePath();
    };

    const dU = (x, y, sz, root, col) => {
      ctx.beginPath();
      ctx.arc(x, y - sz * 0.3, sz * 0.35, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(x, y + sz * 0.3, sz * 0.5, Math.PI, 0);
      ctx.fillStyle = col;
      ctx.fill();

      if (root) {
        ctx.fillStyle = "#fbbf24";
        ctx.font = `${Math.max(7, sz * 0.6)}px ${MONO}`;
        ctx.textAlign = "center";
        ctx.fillText("★", x, y - sz * 0.65);
      }
    };

    const resize = () => {
      const parent = cv.parentElement;
      if (!parent) return;
      const r = parent.getBoundingClientRect();
      if (!r.width || !r.height) return;
      w = r.width;
      h = r.height;
      cv.width = w * dpr;
      cv.height = h * dpr;
      cv.style.width = `${w}px`;
      cv.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      sos.length = 0;
      const sp = w / 5;
      for (let i = 0; i < 4; i += 1) sos.push({ bx: sp * (i + 1), by: h * 0.6, x: 0, y: 0 });
    };

    resize();
    const parent = cv.parentElement;
    const ro = typeof ResizeObserver !== "undefined" && parent ? new ResizeObserver(resize) : null;
    if (ro && parent) ro.observe(parent);
    const vv = window.visualViewport;
    window.addEventListener("resize", resize);
    if (vv) vv.addEventListener("resize", resize);

    const draw = () => {
      timeRef.current += 0.012;
      const t = timeRef.current;
      ctx.clearRect(0, 0, w, h);

      ctx.strokeStyle = "rgba(99,102,241,0.03)";
      ctx.lineWidth = 1;

      for (let gx = 0; gx < w; gx += 40) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, h);
        ctx.stroke();
      }

      for (let gy = 0; gy < h; gy += 40) {
        ctx.beginPath();
        ctx.moveTo(0, gy);
        ctx.lineTo(w, gy);
        ctx.stroke();
      }

      const px = w / 2;
      const py = h * 0.16;
      const pw = Math.min(220, w * 0.35);
      const ph = 68;
      const pd = Math.sin(t * 0.4) * 1.5;

      rr(px - pw / 2 + pd, py - ph / 2, pw, ph, 8);
      ctx.fillStyle = "rgba(99,102,241,0.06)";
      ctx.fill();
      ctx.strokeStyle = "rgba(99,102,241,0.2)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.font = `700 10px ${MONO}`;
      ctx.fillStyle = "#a5b4fc";
      ctx.textAlign = "center";
      ctx.fillText("PARENT ORG", px + pd, py - ph / 2 - 8);

      dU(px - 28 + pd, py - 6, 10, true, "#6366f1");
      ctx.font = `500 7px ${MONO}`;
      ctx.fillStyle = "rgba(255,255,255,0.4)";
      ctx.textAlign = "center";
      ctx.fillText("Root", px - 28 + pd, py + 16);

      dU(px + 12 + pd, py - 6, 10, false, "#475569");
      ctx.fillText("Non-root", px + 12 + pd, py + 16);

      ctx.font = `600 7px ${MONO}`;
      ctx.fillStyle = "rgba(251,191,36,0.7)";
      ctx.fillText("READ-ONLY ↓", px + pd, py + ph / 2 + 14);

      const soW = Math.min(120, (w - 40) / 4 - 12);
      const soH = 100;
      const posArr = [];

      sos.forEach((so, si) => {
        const dr = Math.sin(t * 0.3 + si * 1.2) * 2;
        so.x = so.bx + dr;
        so.y = so.by + Math.cos(t * 0.4 + si) * 1.5;
        const wd = WALLET_DATA[si];
        const actors = getActorsForSubOrg(wd.id);

        const isSel = selectedWallet && selectedWallet.id === wd.id;

        ctx.strokeStyle = "rgba(251,191,36,0.12)";
        ctx.lineWidth = 1;
        ctx.setLineDash([3, 5]);
        ctx.beginPath();
        ctx.moveTo(px + pd, py + ph / 2 + 18);
        ctx.quadraticCurveTo((px + pd + so.x) / 2, (py + ph / 2 + 18 + so.y - soH / 2) / 2 + 10, so.x, so.y - soH / 2);
        ctx.stroke();
        ctx.setLineDash([]);

        const rp = (t * 0.2 + si * 0.25) % 1;
        const rpMX = (px + pd + so.x) / 2;
        const rpMY = (py + ph / 2 + 18 + so.y - soH / 2) / 2 + 10;
        const rpX = (1 - rp) * (1 - rp) * (px + pd) + 2 * (1 - rp) * rp * rpMX + rp * rp * so.x;
        const rpY = (1 - rp) * (1 - rp) * (py + ph / 2 + 18) + 2 * (1 - rp) * rp * rpMY + rp * rp * (so.y - soH / 2);

        ctx.beginPath();
        ctx.arc(rpX, rpY, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(251,191,36,${0.5 - rp * 0.4})`;
        ctx.fill();

        const sl = so.x - soW / 2;
        const st2 = so.y - soH / 2;
        rr(sl, st2, soW, soH, 6);

        ctx.fillStyle = isSel
          ? "rgba(99,102,241,0.08)"
          : isBlk
            ? "rgba(239,68,68,0.03)"
            : "rgba(99,102,241,0.03)";
        ctx.fill();

        ctx.strokeStyle = isSel
          ? "rgba(99,102,241,0.6)"
          : isBlk
            ? "rgba(239,68,68,0.25)"
            : hasCon
              ? "rgba(99,102,241,0.3)"
              : "rgba(99,102,241,0.12)";
        ctx.lineWidth = isSel ? 2 : 1.5;
        ctx.stroke();

        if (isSel) {
          const sg = ctx.createRadialGradient(so.x, so.y, 10, so.x, so.y, soW * 0.8);
          sg.addColorStop(0, "rgba(99,102,241,0.08)");
          sg.addColorStop(1, "rgba(0,0,0,0)");
          ctx.beginPath();
          ctx.arc(so.x, so.y, soW * 0.8, 0, Math.PI * 2);
          ctx.fillStyle = sg;
          ctx.fill();
        }

        ctx.font = `600 8px ${MONO}`;
        ctx.fillStyle = isBlk ? "rgba(239,68,68,0.6)" : "rgba(165,180,252,0.7)";
        ctx.textAlign = "center";
        ctx.fillText(`SUB-ORG ${si + 1}`, so.x, st2 - 6);

        const actorGap = 2;
        const actorTileW = (soW - 12 - actorGap * 2) / 3;
        const actorTileH = 22;
        const actorY = so.y - 4;
        const actorHitboxes = [];

        actors.forEach((actor, ai) => {
          const ax = sl + 6 + ai * (actorTileW + actorGap);
          const ay = actorY;
          const roleColor = ACTOR_COLORS[actor.role] || "#64748b";
          const isActorSel = isSel && actor.id === selectedActorId;

          rr(ax, ay, actorTileW, actorTileH, 3);
          ctx.fillStyle = isBlk ? "rgba(239,68,68,0.08)" : isActorSel ? `${roleColor}35` : `${roleColor}14`;
          ctx.fill();
          ctx.strokeStyle = isActorSel ? roleColor : `${roleColor}99`;
          ctx.lineWidth = isActorSel ? 1.4 : 0.9;
          ctx.stroke();

          ctx.font = `600 6px ${MONO}`;
          ctx.fillStyle = roleColor;
          ctx.textAlign = "center";
          ctx.fillText(actor.short, ax + actorTileW / 2, ay + 8);
          ctx.font = `500 5px ${MONO}`;
          ctx.fillStyle = "rgba(226,232,240,0.7)";
          ctx.fillText("wallet", ax + actorTileW / 2, ay + 15.5);
          ctx.fillStyle = "rgba(148,163,184,0.55)";
          ctx.fillText(shortenAddress(actor.walletAddress), ax + actorTileW / 2, ay + 21);

          actorHitboxes.push({ id: actor.id, x: ax, y: ay, w: actorTileW, h: actorTileH });
        });

        posArr.push({ subOrg: wd, card: { x: so.x, y: so.y, w: soW, h: soH }, actors: actorHitboxes });

        ctx.font = `500 6px ${MONO}`;
        ctx.fillStyle = "rgba(148,163,184,0.4)";
        ctx.fillText(wd.chain, so.x, st2 + soH + 10);

        if (hasCon && !isBlk) {
          rr(sl + 3, st2 + 3, soW - 6, soH - 6, 4);
          ctx.strokeStyle = `rgba(99,102,241,${0.15 + Math.sin(t * 2 + si) * 0.08})`;
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        if (!isSel) {
          ctx.font = `500 6px ${MONO}`;
          ctx.fillStyle = `rgba(99,102,241,${0.2 + Math.sin(t * 2 + si * 0.5) * 0.1})`;
          ctx.textAlign = "center";
          ctx.fillText("click wallet tiles", so.x, st2 + soH + 20);
        }
      });

      soPos.current = posArr;

      const cY = h * 0.88;
      const cSp = w / (uTargets.length + 1);

      uTargets.forEach((ta, i) => {
        const cx2 = cSp * (i + 1) + Math.sin(t * 0.5 + i) * 3;
        const cy2 = cY + Math.cos(t * 0.6 + i) * 2;
        const ok = ta.isAllow && !hasD;

        sos.forEach((so, si) => {
          const wY2 = so.y + 30;
          if (ok) {
            ctx.strokeStyle = "rgba(52,211,153,0.3)";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(so.x, wY2);
            ctx.lineTo(cx2, cy2 - 14);
            ctx.stroke();
            const pp = (t * (0.2 + si * 0.05) + si * 0.15) % 1;
            ctx.beginPath();
            ctx.arc(so.x + (cx2 - so.x) * pp, wY2 + (cy2 - 14 - wY2) * pp, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = "#34d399";
            ctx.fill();
          } else {
            ctx.strokeStyle = "rgba(239,68,68,0.15)";
            ctx.lineWidth = 1;
            ctx.setLineDash([3, 4]);
            const r2 = 0.3 + Math.sin(t * 2 + si) * 0.08;
            ctx.beginPath();
            ctx.moveTo(so.x, wY2);
            ctx.lineTo(so.x + (cx2 - so.x) * r2, wY2 + (cy2 - 14 - wY2) * r2);
            ctx.stroke();
            ctx.setLineDash([]);
          }
        });

        const g = ctx.createRadialGradient(cx2, cy2, 6, cx2, cy2, 22);
        g.addColorStop(0, `rgba(${ok ? "52,211,153" : "239,68,68"},0.12)`);
        g.addColorStop(1, "rgba(0,0,0,0)");
        ctx.beginPath();
        ctx.arc(cx2, cy2, 22, 0, Math.PI * 2);
        ctx.fillStyle = g;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(cx2, cy2, 14, 0, Math.PI * 2);
        ctx.fillStyle = ok ? "#34d399" : "#ef4444";
        ctx.fill();
        ctx.strokeStyle = ok ? "rgba(52,211,153,0.5)" : "rgba(239,68,68,0.5)";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.font = `600 8px ${MONO}`;
        ctx.fillStyle = "rgba(255,255,255,0.5)";
        ctx.textAlign = "center";
        ctx.fillText(ta.targetLabel, cx2, cy2 + 24);
      });

      if (!policies.length) {
        const gX = w * 0.82;
        const gY = h * 0.85;
        ctx.beginPath();
        ctx.arc(gX, gY, 12, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(148,163,184,0.1)";
        ctx.fill();
        ctx.strokeStyle = "rgba(148,163,184,0.15)";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.font = `500 8px ${MONO}`;
        ctx.fillStyle = "rgba(148,163,184,0.3)";
        ctx.textAlign = "center";
        ctx.fillText("External", gX, gY + 20);

        sos.forEach((so, si) => {
          ctx.strokeStyle = "rgba(239,68,68,0.15)";
          ctx.lineWidth = 1;
          ctx.setLineDash([3, 5]);
          const r3 = 0.25 + Math.sin(t * 2.5 + si) * 0.08;
          ctx.beginPath();
          ctx.moveTo(so.x, so.y + 30);
          ctx.lineTo(so.x + (gX - so.x) * r3, so.y + 30 + (gY - so.y - 30) * r3);
          ctx.stroke();
          ctx.setLineDash([]);
          const bx = so.x + (gX - so.x) * r3;
          const by = so.y + 30 + (gY - so.y - 30) * r3;
          ctx.beginPath();
          ctx.arc(bx, by, 4, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(239,68,68,${0.2 + Math.sin(t * 3 + si) * 0.1})`;
          ctx.fill();
        });
      }

      const sw = swRef.current;
      if (sw.active) {
        sw.radius += 4;
        sw.opacity = Math.max(0, 1 - sw.radius / (Math.max(w, h) * 0.6));
        ctx.beginPath();
        ctx.arc(w / 2, h * 0.6, sw.radius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(239,68,68,${sw.opacity * 0.5})`;
        ctx.lineWidth = 2.5;
        ctx.stroke();
        if (sw.opacity <= 0) sw.active = false;
      }

      let bt;
      let bc;

      if (!policies.length) {
        bt = "⛔ IMPLICIT DENY";
        bc = "#ef4444";
      } else if (hasGD || (hasD && !hasA)) {
        bt = "⛔ GLOBAL DENY";
        bc = "#ef4444";
      } else if (dWins) {
        bt = "⚡ DENY WINS";
        bc = "#f59e0b";
      } else if (hasCon) {
        bt = "🔐 CONSENSUS";
        bc = "#6366f1";
      } else if (uTargets.length) {
        bt = "🏰 RESTRICTED";
        bc = "#f59e0b";
      } else if (hasA) {
        bt = "✅ ALLOWED";
        bc = "#34d399";
      } else {
        bt = "⏸ IDLE";
        bc = "#64748b";
      }

      ctx.font = `700 10px ${MONO}`;
      const bw2 = ctx.measureText(bt).width + 20;

      if (typeof ctx.roundRect === "function") {
        ctx.fillStyle = `${bc}18`;
        ctx.beginPath();
        ctx.roundRect(w - bw2 - 14, 12, bw2, 24, 5);
        ctx.fill();
        ctx.strokeStyle = `${bc}44`;
        ctx.lineWidth = 1;
        ctx.stroke();
      } else {
        rr(w - bw2 - 14, 12, bw2, 24, 5);
        ctx.fillStyle = `${bc}18`;
        ctx.fill();
        ctx.strokeStyle = `${bc}44`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      ctx.fillStyle = bc;
      ctx.textAlign = "center";
      ctx.fillText(bt, w - bw2 / 2 - 14, 29);

      ctx.font = `500 9px ${MONO}`;
      ctx.fillStyle = "#475569";
      ctx.textAlign = "left";
      ctx.fillText(`${policies.length} polic${policies.length === 1 ? "y" : "ies"} active`, 14, 26);

      ctx.font = `500 7px ${MONO}`;
      ctx.fillStyle = "rgba(251,191,36,0.35)";
      ctx.fillText("Parent: READ-ONLY to Sub-Orgs · Policies scope to Sub-Org level", 14, h - 8);

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
      if (vv) vv.removeEventListener("resize", resize);
      if (ro) ro.disconnect();
      cancelAnimationFrame(animRef.current);
    };
  }, [policies, parsed, hasGD, hasD, hasA, hasCon, dWins, uTargets, isBlk, selectedWallet, selectedActorId]);

  return (
    <canvas
      ref={canvasRef}
      onClick={onClick}
      style={{ width: "100%", height: "100%", display: "block", background: "#0a0a1a", cursor: "pointer" }}
    />
  );
}

function PolicyForm({ onAdd, onClose }) {
  const [n, sn] = useState("");
  const [ef, se] = useState("EFFECT_ALLOW");
  const [co, sc] = useState("");
  const [cs, scs] = useState("");

  return (
    <div style={{ padding: "14px", display: "flex", flexDirection: "column", gap: "10px" }}>
      <div>
        <div style={lblSt}>Policy Name</div>
        <input style={inputSt} value={n} onChange={(e) => sn(e.target.value)} placeholder="my-policy" />
      </div>

      <div>
        <div style={lblSt}>Effect</div>
        <div style={{ display: "flex", gap: "6px" }}>
          {["EFFECT_ALLOW", "EFFECT_DENY"].map((e) => (
            <button
              key={e}
              onClick={() => se(e)}
              style={{
                flex: 1,
                padding: "7px",
                fontSize: "11px",
                fontFamily: MONO,
                fontWeight: 600,
                border: ef === e ? `1px solid ${e === "EFFECT_ALLOW" ? "#34d399" : "#ef4444"}` : "1px solid rgba(99,102,241,0.15)",
                borderRadius: "4px",
                background: ef === e
                  ? e === "EFFECT_ALLOW"
                    ? "rgba(52,211,153,0.12)"
                    : "rgba(239,68,68,0.12)"
                  : "transparent",
                color: ef === e ? (e === "EFFECT_ALLOW" ? "#34d399" : "#f87171") : "#64748b",
                cursor: "pointer",
              }}
            >
              {e === "EFFECT_ALLOW" ? "✓ ALLOW" : "✕ DENY"}
            </button>
          ))}
        </div>
      </div>

      <div>
        <div style={lblSt}>Condition</div>
        <textarea
          style={{ ...inputSt, minHeight: "50px", resize: "vertical" }}
          value={co}
          onChange={(e) => sc(e.target.value)}
          placeholder="eth.tx.to == '0x...'"
        />
      </div>

      <div>
        <div style={lblSt}>Consensus</div>
        <textarea
          style={{ ...inputSt, minHeight: "38px", resize: "vertical" }}
          value={cs}
          onChange={(e) => scs(e.target.value)}
          placeholder="approvers.any(user, user.id == '...')"
        />
      </div>

      <div style={{ display: "flex", gap: "6px" }}>
        <button
          onClick={() => {
            if (n.trim()) {
              onAdd({ policyName: n.trim(), effect: ef, condition: co.trim(), consensus: cs.trim() });
              onClose();
            }
          }}
          style={{
            flex: 1,
            padding: "8px",
            fontSize: "11px",
            fontFamily: MONO,
            fontWeight: 700,
            border: "none",
            borderRadius: "5px",
            background: "rgba(99,102,241,0.25)",
            color: "#a5b4fc",
            cursor: "pointer",
          }}
        >
          Add Policy
        </button>
        <button
          onClick={onClose}
          style={{
            padding: "8px 12px",
            fontSize: "11px",
            fontFamily: MONO,
            border: "1px solid rgba(99,102,241,0.12)",
            borderRadius: "5px",
            background: "transparent",
            color: "#64748b",
            cursor: "pointer",
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function PolicyCard({ policy, onRemove }) {
  const p = parsePolicy(policy);
  return (
    <div
      style={{
        padding: "9px 11px",
        background: p.isDeny ? "rgba(239,68,68,0.06)" : "rgba(99,102,241,0.04)",
        borderLeft: `3px solid ${p.isDeny ? "#ef4444" : "#34d399"}`,
        borderRadius: "0 4px 4px 0",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: "11px", fontWeight: 600, color: "#e2e8f0", marginBottom: 2 }}>{policy.policyName}</div>
          <div style={{ display: "flex", gap: "3px", flexWrap: "wrap", marginBottom: 2 }}>
            <span
              style={{
                fontSize: "7px",
                padding: "1px 4px",
                borderRadius: "2px",
                fontWeight: 700,
                background: p.isDeny ? "rgba(239,68,68,0.15)" : "rgba(52,211,153,0.15)",
                color: p.isDeny ? "#f87171" : "#34d399",
              }}
            >
              {policy.effect}
            </span>
            {p.hasCond && (
              <span
                style={{
                  fontSize: "7px",
                  padding: "1px 4px",
                  borderRadius: "2px",
                  background: "rgba(245,158,11,0.12)",
                  color: "#fbbf24",
                }}
              >
                COND
              </span>
            )}
            {p.needsApproval && (
              <span
                style={{
                  fontSize: "7px",
                  padding: "1px 4px",
                  borderRadius: "2px",
                  background: "rgba(99,102,241,0.15)",
                  color: "#a5b4fc",
                }}
              >
                CONS
              </span>
            )}
            {p.chain && (
              <span
                style={{
                  fontSize: "7px",
                  padding: "1px 4px",
                  borderRadius: "2px",
                  background: "rgba(148,163,184,0.1)",
                  color: "#94a3b8",
                }}
              >
                {p.chain}
              </span>
            )}
          </div>
          <div style={{ fontSize: "9px", color: "#64748b" }}>
            {p.condSum}
            {p.consSum ? ` · ${p.consSum}` : ""}
          </div>
        </div>
        <button
          onClick={() => onRemove(policy._id)}
          style={{ background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: "14px", padding: "0 2px" }}
        >
          x
        </button>
      </div>
      {(policy.condition || policy.consensus) && (
        <div
          style={{
            marginTop: 5,
            padding: "4px 6px",
            background: "rgba(0,0,0,0.25)",
            borderRadius: "3px",
            fontSize: "9px",
            fontFamily: MONO,
            color: "#94a3b8",
            lineHeight: 1.5,
            wordBreak: "break-all",
          }}
        >
          {policy.condition && (
            <div>
              <span style={{ color: "#6366f1" }}>cond:</span> {policy.condition}
            </div>
          )}
          {policy.consensus && (
            <div>
              <span style={{ color: "#6366f1" }}>cons:</span> {policy.consensus}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EvalLog({ policies, selectedWallet, selectedActorId, latestEval }) {
  if (!policies.length) {
    return (
      <div style={{ padding: "16px", fontSize: "10px", color: "#475569" }}>
        <span style={{ color: "#ef4444" }}>No policies.</span> Implicit deny.
      </div>
    );
  }

  if (!selectedWallet) {
    return (
      <div style={{ padding: "16px", fontSize: "10px", color: "#64748b", lineHeight: 1.6 }}>
        <div style={{ color: "#6366f1", fontWeight: 700, textTransform: "uppercase", marginBottom: 8 }}>Eval Engine</div>
        Select a Sub-Org wallet tile on the map, then run a simulation to see the exact step-by-step engine output here.
      </div>
    );
  }

  const selectedActor =
    getActorsForSubOrg(selectedWallet.id).find((a) => a.id === selectedActorId) || getActorsForSubOrg(selectedWallet.id)[0] || null;
  const matchesCurrentContext =
    !!latestEval &&
    latestEval.walletId === selectedWallet.id &&
    latestEval.actorId === (selectedActor?.id || null) &&
    latestEval.result;

  if (!matchesCurrentContext) {
    return (
      <div style={{ padding: "16px", fontSize: "10px", color: "#64748b", lineHeight: 1.6 }}>
        <div style={{ color: "#6366f1", fontWeight: 700, textTransform: "uppercase", marginBottom: 8 }}>Eval Engine</div>
        <div style={{ color: "#94a3b8", marginBottom: 6 }}>
          Context: {selectedWallet.name} · {selectedActor ? selectedActor.short : "N/A"}
        </div>
        Run <span style={{ color: "#a5b4fc" }}>Simulate Transaction</span> in the right panel to sync the exact evaluation
        trace here.
      </div>
    );
  }

  const tx = latestEval.tx || {};
  const result = latestEval.result;
  const rc = { ALLOWED: "#34d399", DENIED: "#ef4444", PENDING: "#6366f1" };
  const rl = {
    ALLOWED: "TRANSACTION ALLOWED",
    DENIED: "TRANSACTION DENIED",
    PENDING: "AWAITING APPROVAL",
  };

  return (
    <div style={{ padding: "16px", fontSize: "10px", color: "#94a3b8", lineHeight: 1.6, fontFamily: MONO }}>
      <div style={{ color: "#6366f1", fontWeight: 700, textTransform: "uppercase", marginBottom: 8 }}>Eval Engine</div>
      <div style={{ color: "#64748b", marginBottom: 2 }}>
        Context: {selectedWallet.name} · {selectedActor ? selectedActor.short : "N/A"}
      </div>
      <div style={{ color: "#64748b", marginBottom: 8 }}>
        Action: {tx.action || "N/A"} · Resource: {tx.resource || "N/A"}
      </div>

      <div
        style={{
          padding: "8px 9px",
          borderRadius: "6px",
          marginBottom: 8,
          background: `${rc[result.final] || "#64748b"}12`,
          border: `1px solid ${rc[result.final] || "#64748b"}33`,
        }}
      >
        <div style={{ fontSize: "11px", fontWeight: 700, color: rc[result.final] }}>
          {result.final === "ALLOWED" ? "✅" : result.final === "DENIED" ? "⛔" : "🔐"} {rl[result.final]}
        </div>
      </div>

      <div style={{ color: "#6366f1", fontWeight: 700, textTransform: "uppercase", marginBottom: 4 }}>Evaluation Steps</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
        {result.steps.map((st, i) => {
          const sc =
            st.res === "ALLOW"
              ? "#34d399"
              : st.res === "DENY" || st.res === "OVERRIDE"
                ? "#ef4444"
                : st.res === "PENDING"
                  ? "#6366f1"
                  : "#475569";
          return (
            <div
              key={i}
              style={{
                padding: "5px 7px",
                borderRadius: "3px",
                fontSize: "9px",
                background: st.res === "OVERRIDE" ? "rgba(239,68,68,0.08)" : "rgba(0,0,0,0.2)",
                borderLeft: `2px solid ${sc}`,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "#94a3b8" }}>{st.pol || "ENGINE"}</span>
                <span
                  style={{
                    fontSize: "7px",
                    fontWeight: 700,
                    color: sc,
                    padding: "1px 4px",
                    borderRadius: "2px",
                    background: `${sc}18`,
                  }}
                >
                  {st.res}
                </span>
              </div>
              <div style={{ color: "#64748b", fontSize: "8px", marginTop: 1 }}>{st.why}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function LangRefPanel({ onClose }) {
  return (
    <div style={{ padding: "16px", overflow: "auto", flex: 1 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{ fontSize: "12px", fontWeight: 700, color: "#e2e8f0" }}>Policy Language Ref</div>
        <button
          onClick={onClose}
          style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: "14px" }}
        >
          x
        </button>
      </div>
      {[
        { t: "Condition Keywords", d: Object.entries(LANG_REF.condKw).map(([k, v]) => `${k} → ${v}`) },
        { t: "Consensus", d: Object.entries(LANG_REF.consKw).map(([k, v]) => `${k} → ${v}`) },
        { t: "Operators", d: [LANG_REF.ops] },
        { t: "List Functions", d: [LANG_REF.listFn] },
      ].map((s) => (
        <div key={s.t} style={{ marginBottom: 12 }}>
          <div
            style={{
              fontSize: "9px",
              fontWeight: 700,
              color: "#6366f1",
              textTransform: "uppercase",
              marginBottom: 4,
            }}
          >
            {s.t}
          </div>
          {s.d.map((i, j) => (
            <div key={j} style={{ fontSize: "10px", color: "#94a3b8", fontFamily: MONO }}>
              {i}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

export default function TurnkeyPolicySandbox() {
  const [policies, dispatch] = useReducer(policiesReducer, []);
  const [view, setView] = useState("policies");
  const [tab, setTab] = useState("editor");
  const [exFilt, setExFilt] = useState(null);
  const [selW, setSelW] = useState(null);
  const [selActorId, setSelActorId] = useState(null);
  const [latestEval, setLatestEval] = useState(null);
  const [viewportW, setViewportW] = useState(() => getViewportWidth());

  const addP = (p) => dispatch({ type: "ADD", policy: p });
  const rmP = (id) => dispatch({ type: "REMOVE", id });
  const selectedTemplateContext = getSelectedTemplateContext(selW, selActorId);
  const activeHeaderActor = selW
    ? getActorsForSubOrg(selW.id).find((a) => a.id === selActorId) || getActorsForSubOrg(selW.id)[0]
    : null;

  const handleSelectWallet = useCallback((wallet, actorId) => {
    if (!wallet) return;
    setSelW(wallet);
    setSelActorId(actorId || getDefaultActorId(wallet.id));
    setLatestEval(null);
  }, []);

  useEffect(() => {
    setLatestEval(null);
  }, [policies]);

  useEffect(() => {
    const onResize = () => setViewportW(getViewportWidth());
    const vv = window.visualViewport;
    onResize();
    window.addEventListener("resize", onResize);
    if (vv) vv.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      if (vv) vv.removeEventListener("resize", onResize);
    };
  }, []);

  const isTablet = viewportW < 1280;
  const isMobile = viewportW < 960;

  return (
    <div
      style={{
        width: "100%",
        height: "100dvh",
        background: "#06061a",
        color: "#e2e8f0",
        fontFamily: MONO,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: isMobile ? "6px" : "8px",
          padding: isMobile ? "8px 10px" : "10px 20px",
          borderBottom: "1px solid rgba(99,102,241,0.1)",
          background: "rgba(6,6,26,0.95)",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: 0 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#6366f1", boxShadow: "0 0 8px #6366f1" }} />
          <span style={{ fontWeight: 700, fontSize: "13px", letterSpacing: "0.05em" }}>TURNKEY</span>
          <span style={{ fontSize: "11px", color: "#64748b" }}>Policy Sandbox</span>
        </div>
        <div style={{ display: "flex", gap: "6px", alignItems: "center", minWidth: 0, marginLeft: "auto" }}>
          {selW && (
            <span
              style={{
                fontSize: "9px",
                color: "#6366f1",
                maxWidth: isMobile ? "48vw" : isTablet ? "28vw" : "none",
                whiteSpace: "nowrap",
                textOverflow: "ellipsis",
                overflow: "hidden",
              }}
            >
              Inspecting: {selW.name}
              {activeHeaderActor ? ` · ${activeHeaderActor.short}` : ""}
            </span>
          )}
          <button
            onClick={() => {
              dispatch({ type: "CLEAR" });
              setLatestEval(null);
            }}
            style={{
              padding: "5px 10px",
              fontSize: "10px",
              fontFamily: MONO,
              border: "1px solid rgba(239,68,68,0.2)",
              borderRadius: "4px",
              background: "transparent",
              color: "#f87171",
              cursor: "pointer",
            }}
          >
            Clear All
          </button>
        </div>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: isMobile ? "column" : "row",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: isMobile ? "100%" : selW ? (isTablet ? "34%" : "30%") : isTablet ? "40%" : "36%",
            minWidth: isMobile ? 0 : isTablet ? 220 : 260,
            maxWidth: isMobile ? "100%" : selW ? (isTablet ? "420px" : "460px") : "520px",
            flex: isMobile ? (selW ? "0 0 34%" : "0 0 42%") : "0 1 auto",
            display: "flex",
            flexDirection: "column",
            borderRight: isMobile ? "none" : "1px solid rgba(99,102,241,0.1)",
            borderBottom: isMobile ? "1px solid rgba(99,102,241,0.1)" : "none",
            background: "#0a0a1f",
            transition: isMobile ? "none" : "width 0.3s",
          }}
        >
          <div style={{ display: "flex", borderBottom: "1px solid rgba(99,102,241,0.08)", flexShrink: 0 }}>
            {[
              { id: "editor", l: "Editor" },
              { id: "eval", l: "Eval Log" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  flex: 1,
                  padding: "10px",
                  fontSize: "10px",
                  fontFamily: MONO,
                  fontWeight: tab === t.id ? 700 : 400,
                  border: "none",
                  borderBottom: tab === t.id ? "2px solid #6366f1" : "2px solid transparent",
                  background: "transparent",
                  color: tab === t.id ? "#a5b4fc" : "#475569",
                  cursor: "pointer",
                }}
              >
                {t.l}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflow: "auto" }}>
            {tab === "eval" ? (
              <EvalLog
                policies={policies}
                selectedWallet={selW}
                selectedActorId={selActorId}
                latestEval={latestEval}
              />
            ) : view === "form" ? (
              <PolicyForm onAdd={addP} onClose={() => setView("policies")} />
            ) : view === "reference" ? (
              <LangRefPanel onClose={() => setView("policies")} />
            ) : view === "examples" ? (
              <div style={{ padding: "14px", overflow: "auto" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <div style={{ fontSize: "12px", fontWeight: 700 }}>Policy Examples</div>
                  <button
                    onClick={() => setView("policies")}
                    style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: "14px" }}
                  >
                    x
                  </button>
                </div>
                <div style={{ fontSize: "9px", color: "#475569", marginBottom: 8 }}>
                  From <span style={{ color: "#6366f1" }}>docs.turnkey.com</span> — click to add.
                </div>
                <div style={{ fontSize: "8px", color: "#64748b", marginBottom: 8 }}>
                  {selectedTemplateContext
                    ? `Injecting from: ${selectedTemplateContext.subOrgName} · ${selectedTemplateContext.actorShort} · ${selectedTemplateContext.userId}`
                    : "No map selection: placeholders will stay as-is"}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "3px", marginBottom: 8 }}>
                  <button onClick={() => setExFilt(null)} style={pill(!exFilt)}>
                    All
                  </button>
                  {CATS.map((c) => (
                    <button key={c.name} onClick={() => setExFilt(c.name)} style={pill(exFilt === c.name)}>
                      {c.name}
                    </button>
                  ))}
                </div>
                {CATS.filter((c) => !exFilt || c.name === exFilt).map((cat) => (
                  <div key={cat.name} style={{ marginBottom: 10 }}>
                    <div
                      style={{
                        fontSize: "9px",
                        fontWeight: 700,
                        color: "#6366f1",
                        textTransform: "uppercase",
                        marginBottom: 4,
                        paddingBottom: 3,
                        borderBottom: "1px solid rgba(99,102,241,0.08)",
                      }}
                    >
                      {cat.name} ({cat.examples.length})
                    </div>
                    {cat.examples.map((ex, i) => (
                      <button
                        key={i}
                        onClick={() => {
                          const hydratedPolicy = resolveExamplePolicy(ex.policy, selectedTemplateContext);
                          addP(hydratedPolicy);
                          setView("policies");
                        }}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          width: "100%",
                          padding: "6px 8px",
                          marginBottom: 2,
                          fontSize: "10px",
                          fontFamily: MONO,
                          border: "1px solid rgba(99,102,241,0.08)",
                          borderRadius: "3px",
                          background: "rgba(99,102,241,0.03)",
                          color: "#c4b5fd",
                          cursor: "pointer",
                          textAlign: "left",
                          gap: "6px",
                        }}
                      >
                        <span style={{ flex: 1 }}>{ex.label}</span>
                        <span
                          style={{
                            fontSize: "7px",
                            padding: "1px 4px",
                            borderRadius: "2px",
                            fontWeight: 700,
                            background:
                              ex.policy.effect === "EFFECT_DENY" ? "rgba(239,68,68,0.12)" : "rgba(52,211,153,0.12)",
                            color: ex.policy.effect === "EFFECT_DENY" ? "#f87171" : "#34d399",
                          }}
                        >
                          {ex.policy.effect === "EFFECT_DENY" ? "DENY" : "ALLOW"}
                        </span>
                      </button>
                    ))}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: "12px" }}>
                {!policies.length && (
                  <div style={{ fontSize: "11px", color: "#475569", padding: "20px 0", textAlign: "center", lineHeight: 1.7 }}>
                    No policies.
                    <br />
                    <span style={{ color: "#ef4444" }}>Implicit deny.</span>
                    <br />
                    Add a policy to begin.
                  </div>
                )}
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {policies.map((p) => (
                    <PolicyCard key={p._id} policy={p} onRemove={rmP} />
                  ))}
                </div>
              </div>
            )}
          </div>

          {tab === "editor" && view === "policies" && (
            <div
              style={{
                padding: "10px 12px",
                borderTop: "1px solid rgba(99,102,241,0.08)",
                display: "flex",
                gap: "4px",
                flexWrap: isMobile ? "wrap" : "nowrap",
                flexShrink: 0,
              }}
            >
              <button
                onClick={() => setView("form")}
                style={{
                  flex: 1,
                  padding: "8px",
                  fontSize: "10px",
                  fontFamily: MONO,
                  fontWeight: 700,
                  border: "none",
                  borderRadius: "4px",
                  background: "rgba(99,102,241,0.2)",
                  color: "#a5b4fc",
                  cursor: "pointer",
                }}
              >
                + Custom
              </button>
              <button
                onClick={() => setView("examples")}
                style={{
                  padding: "8px 10px",
                  fontSize: "10px",
                  fontFamily: MONO,
                  border: "1px solid rgba(99,102,241,0.12)",
                  borderRadius: "4px",
                  background: "transparent",
                  color: "#818cf8",
                  cursor: "pointer",
                }}
              >
                Examples
              </button>
              <button
                onClick={() => setView("reference")}
                style={{
                  padding: "8px 10px",
                  fontSize: "10px",
                  fontFamily: MONO,
                  border: "1px solid rgba(99,102,241,0.12)",
                  borderRadius: "4px",
                  background: "transparent",
                  color: "#818cf8",
                  cursor: "pointer",
                }}
              >
                Ref
              </button>
            </div>
          )}
        </div>

        <div
          style={{
            flex: isMobile ? (selW ? "0 0 36%" : "1 1 auto") : 1,
            minHeight: 220,
            position: "relative",
          }}
        >
          <GalaxyCanvas
            policies={policies}
            selectedWallet={selW}
            selectedActorId={selActorId}
            onSelectWallet={handleSelectWallet}
          />
          <div
            style={{
              position: "absolute",
              bottom: 8,
              left: 10,
              right: 10,
              display: "flex",
              gap: isMobile ? "6px" : "10px",
              fontSize: isMobile ? "7px" : "8px",
              color: "#475569",
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            {[
              { c: "#6366f1", l: "Parent" },
              { c: "#818cf8", l: "Sub-Org" },
              { c: "#fbbf24", l: "Root wallet" },
              { c: "#38bdf8", l: "API robot wallet" },
              { c: "#a78bfa", l: "OAuth wallet" },
              { c: "#34d399", l: "Allowed" },
              { c: "#ef4444", l: "Blocked" },
            ].map((l) => (
              <span key={l.l}>
                <span
                  style={{
                    display: "inline-block",
                    width: 6,
                    height: 6,
                    borderRadius: "50%",
                    background: l.c,
                    marginRight: 3,
                    verticalAlign: "middle",
                  }}
                />
                {l.l}
              </span>
            ))}
          </div>
        </div>

        {selW && (
          <div
            style={{
              width: isMobile ? "100%" : isTablet ? "32%" : "28%",
              minWidth: isMobile ? 0 : isTablet ? 220 : 250,
              maxWidth: isMobile ? "100%" : isTablet ? "380px" : "430px",
              flex: isMobile ? "0 0 30%" : "0 1 auto",
              borderTop: isMobile ? "1px solid rgba(99,102,241,0.1)" : "none",
            }}
          >
            <WalletDetailPanel
              wallet={selW}
              policies={policies}
              actorId={selActorId}
              onSelectActor={(id) => {
                setSelActorId(id);
                setLatestEval(null);
              }}
              onEvalResult={setLatestEval}
              onClose={() => {
                setSelW(null);
                setSelActorId(null);
                setLatestEval(null);
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
