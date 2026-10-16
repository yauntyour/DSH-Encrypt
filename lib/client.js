//#region src/client/api.ts
const TICKET_KEY = "dsh-encrypt-remember";
/** Send one same-origin JSON request with the optional header ticket. */
async function apiPost(path, payload = {}) {
	const headers = { "content-type": "application/json" };
	const ticket = storedTicket();
	if (ticket !== null) headers["x-dsh-encrypt-remember"] = ticket;
	return await (await fetch(path, {
		method: "POST",
		headers,
		body: JSON.stringify(payload)
	})).json();
}
/** Synchronize the explicit header ticket after an API response. */
function syncTicket(body) {
	if (body.ok !== true) return;
	const value = body.value ?? {};
	if (value.rememberChannel !== "header") {
		storeTicket(null);
		return;
	}
	if (typeof value.ticket === "string" && value.ticket.length > 0) storeTicket(value.ticket);
	else if (value.remembered === false) storeTicket(null);
}
/** Remove an explicit remembered-login ticket. */
function clearStoredTicket() {
	storeTicket(null);
}
function storedTicket() {
	try {
		return typeof localStorage === "undefined" ? null : localStorage.getItem(TICKET_KEY);
	} catch {
		return null;
	}
}
function storeTicket(ticket) {
	try {
		if (typeof localStorage === "undefined") return;
		if (typeof ticket === "string" && ticket.length > 0) localStorage.setItem(TICKET_KEY, ticket);
		else localStorage.removeItem(TICKET_KEY);
	} catch {}
}
/** Map persisted remember days into the finite slider domain. */
function sliderFromDays(days) {
	if (days === -1) return 31;
	return typeof days === "number" && Number.isFinite(days) ? Math.max(0, Math.min(30, days)) : 0;
}
/** Map the slider's forever position back to the persisted marker. */
function daysFromSlider(value) {
	return value === 31 ? -1 : value;
}
/** Human-readable label for one slider position. */
function rememberLabel(value) {
	if (value === 0) return "每次都输入密码";
	if (value === 31) return "永远免密登录（仅本机）";
	return `${value} 天内免密登录（仅本机）`;
}
/** Format a remembered-login expiry timestamp for the settings panel. */
function expiryText(milliseconds) {
	const date = new Date(milliseconds);
	if (Number.isNaN(date.getTime())) return "";
	const month = String(date.getMonth() + 1).padStart(2, "0");
	const day = String(date.getDate()).padStart(2, "0");
	const hour = String(date.getHours()).padStart(2, "0");
	const minute = String(date.getMinutes()).padStart(2, "0");
	return `${date.getFullYear()}-${month}-${day} ${hour}:${minute}`;
}
//#endregion
//#region src/client/sha3.ts
const KECCAK_RC = [
	1n,
	32898n,
	9223372036854808714n,
	9223372039002292224n,
	32907n,
	2147483649n,
	9223372039002292353n,
	9223372036854808585n,
	138n,
	136n,
	2147516425n,
	2147483658n,
	2147516555n,
	9223372036854775947n,
	9223372036854808713n,
	9223372036854808579n,
	9223372036854808578n,
	9223372036854775936n,
	32778n,
	9223372039002259466n,
	9223372039002292353n,
	9223372036854808704n,
	2147483649n,
	9223372039002292232n
];
const KECCAK_RHO = [
	0,
	1,
	62,
	28,
	27,
	36,
	44,
	6,
	55,
	20,
	3,
	10,
	43,
	25,
	39,
	41,
	45,
	15,
	21,
	8,
	18,
	2,
	61,
	56,
	14
];
const KECCAK_PI = [
	0,
	10,
	20,
	5,
	15,
	16,
	1,
	11,
	21,
	6,
	7,
	17,
	2,
	12,
	22,
	23,
	8,
	18,
	3,
	13,
	14,
	24,
	9,
	19,
	4
];
const MASK64 = (1n << 64n) - 1n;
/** Lowercase hexadecimal SHA3-256 of browser text. */
function sha3_256Hex(text) {
	const bytes = new TextEncoder().encode(String(text));
	const rate = 136;
	const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
	padded.set(bytes);
	padded[bytes.length] = 6;
	padded[padded.length - 1] = valueAt(padded, padded.length - 1) | 128;
	let state = Array.from({ length: 25 }).fill(0n);
	for (let offset = 0; offset < padded.length; offset += rate) {
		for (let index = 0; index < rate; index += 8) {
			let word = 0n;
			for (let byte = 0; byte < 8; byte += 1) word |= BigInt(valueAt(padded, offset + index + byte)) << BigInt(8 * byte);
			state[index / 8] = valueAt(state, index / 8) ^ word;
		}
		state = keccakF(state);
	}
	const output = /* @__PURE__ */ new Uint8Array(32);
	for (let index = 0; index < 4; index += 1) {
		let word = valueAt(state, index);
		for (let byte = 0; byte < 8; byte += 1) {
			output[index * 8 + byte] = Number(word & 255n);
			word >>= 8n;
		}
	}
	let hex = "";
	for (const byte of output) hex += byte.toString(16).padStart(2, "0");
	return hex;
}
function keccakF(lanes) {
	for (let round = 0; round < 24; round += 1) {
		const columns = [];
		for (let x = 0; x < 5; x += 1) columns[x] = valueAt(lanes, x) ^ valueAt(lanes, x + 5) ^ valueAt(lanes, x + 10) ^ valueAt(lanes, x + 15) ^ valueAt(lanes, x + 20);
		const deltas = [];
		for (let x = 0; x < 5; x += 1) deltas[x] = valueAt(columns, (x + 4) % 5) ^ rotateLeft(valueAt(columns, (x + 1) % 5), 1);
		for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) {
			const index = x + 5 * y;
			lanes[index] = valueAt(lanes, index) ^ valueAt(deltas, x);
		}
		const rotated = Array.from({ length: 25 }).fill(0n);
		for (let index = 0; index < 25; index += 1) rotated[valueAt(KECCAK_PI, index)] = rotateLeft(valueAt(lanes, index), valueAt(KECCAK_RHO, index));
		for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) {
			const index = x + 5 * y;
			lanes[index] = valueAt(rotated, index) ^ ~valueAt(rotated, (x + 1) % 5 + 5 * y) & valueAt(rotated, (x + 2) % 5 + 5 * y);
		}
		lanes[0] = valueAt(lanes, 0) ^ valueAt(KECCAK_RC, round);
	}
	return lanes;
}
function rotateLeft(value, offset) {
	return (value << BigInt(offset) | value >> BigInt(64 - offset)) & MASK64;
}
function valueAt(values, index) {
	const value = values[index];
	if (value === void 0) throw new RangeError(`index ${index} is outside an array of length ${values.length}`);
	return value;
}
//#endregion
//#region src/client.ts
window.__ModuleLoader__.load({
	id: "dsh-encrypt",
	factory: (require) => {
		const module = { exports: {} };
		const exports = module.exports;
		const React = require("react");
		/**
		* Settings → 加密安全: the browser surface for dsh-encrypt's password
		* lifecycle. Talks to the host over the exact routes the `dsh-encrypt/web`
		* row registers. The raw password never crosses the wire: this bundle
		* derives its SHA3-256 digest (pure JS, Keccak-f[1600]) and POSTs only
		* `{ digest }`.
		*
		* Remembered logins: a slider sets how long a localhost unlock stays
		* valid without the password — 0 = every time, 1..30 days, forever.
		* The server issues an HttpOnly ticket cookie; the panel then
		* auto-unlocks on page load for the configured window. Non-localhost
		* visits always require the password and cannot modify it.
		*
		* States:
		*   plain              — no password set; credentials sit as plaintext
		*                        YAML. Form: set the first password (typed twice).
		*   encrypted+locked   — a password protects the file but this dsh
		*                        process has not unlocked it (restart). Form:
		*                        enter the password to unlock.
		*   encrypted+unlocked — the store is unlocked. Forms: change the
		*                        password, or remove it (back to plaintext).
		* @module dsh-encrypt/client
		*/
		const LABEL = {
			color: "var(--dsw-alias-label-primary)",
			fontSize: 14,
			lineHeight: "22px",
			margin: 0
		};
		const HINT = {
			color: "var(--dsw-alias-label-tertiary)",
			fontSize: 12,
			lineHeight: "18px",
			margin: "8px 0 0"
		};
		const WARN = {
			color: "var(--dsw-alias-state-warn-label)",
			fontSize: 12,
			lineHeight: "18px",
			margin: "8px 0 0"
		};
		const OK = {
			color: "var(--dsw-alias-state-success-primary)",
			fontSize: 12,
			lineHeight: "18px",
			margin: "8px 0 0"
		};
		const FIELD = {
			boxSizing: "border-box",
			width: "100%",
			height: 36,
			margin: "4px 0 0",
			padding: "0 12px",
			border: "1px solid var(--dsw-alias-border-l2)",
			borderRadius: 18,
			background: "var(--dsw-alias-fill-primary)",
			color: "var(--dsw-alias-label-primary)",
			font: "inherit",
			fontSize: 14,
			outline: "none"
		};
		const BUTTON = {
			boxSizing: "border-box",
			height: 36,
			padding: "0 14px",
			margin: "12px 0 0",
			border: "none",
			borderRadius: 18,
			cursor: "pointer",
			font: "inherit",
			fontSize: 14,
			background: "var(--dsw-alias-button-primary-fill)",
			color: "var(--dsw-alias-label-primary-foreground)"
		};
		const CARD = {
			border: "1px solid var(--dsw-alias-border-l2)",
			borderRadius: 12,
			padding: "14px 16px",
			margin: "12px 0 0"
		};
		const ROW = {
			display: "flex",
			flexDirection: "column",
			gap: 12,
			margin: 0
		};
		const SLIDER = {
			width: "100%",
			margin: "10px 0 0",
			cursor: "pointer",
			accentColor: "var(--dsw-alias-button-primary-fill)"
		};
		const SLIDER_MARKS = {
			display: "flex",
			justifyContent: "space-between",
			fontSize: 11,
			color: "var(--dsw-alias-label-tertiary)",
			margin: "4px 0 0"
		};
		function Field(props) {
			return React.createElement("input", {
				type: "password",
				placeholder: props.placeholder,
				value: props.value,
				disabled: props.disabled,
				onChange: (event) => props.onChange(event.target.value),
				style: FIELD
			});
		}
		function Button(props) {
			return React.createElement("button", {
				type: "button",
				disabled: props.disabled,
				onClick: props.onClick,
				style: {
					...BUTTON,
					opacity: props.disabled ? .5 : 1
				}
			}, props.children);
		}
		function pingStatus() {
			apiPost("/api/credentials.status").then((body) => {
				if (body?.ok !== true) return;
				if (body.value?.ticketRejected || body.value?.rememberChannel !== "header") clearStoredTicket();
			}).catch(() => {});
		}
		if (typeof window !== "undefined" && typeof document !== "undefined" && typeof fetch === "function") {
			pingStatus();
			if (document.readyState !== "complete") window.addEventListener("load", () => pingStatus(), { once: true });
			document.addEventListener("visibilitychange", () => {
				if (document.visibilityState === "visible") pingStatus();
			});
			window.addEventListener("focus", () => pingStatus());
		}
		function EncryptionSection(_props) {
			const [status, setStatus] = React.useState(void 0);
			const [busy, setBusy] = React.useState(false);
			const [failure, setFailure] = React.useState(void 0);
			const [notice, setNotice] = React.useState(void 0);
			const [first, setFirst] = React.useState("");
			const [second, setSecond] = React.useState("");
			const [unlockPw, setUnlockPw] = React.useState("");
			const [oldPw, setOldPw] = React.useState("");
			const [slider, setSlider] = React.useState(0);
			const refresh = React.useCallback(async () => {
				try {
					const body = await apiPost("/api/credentials.status");
					if (!body.ok || body.value === void 0) throw new Error(body.message ?? body.code ?? "request failed");
					if (body.value.ticketRejected || body.value.rememberChannel !== "header") clearStoredTicket();
					setStatus(body.value);
					setSlider(sliderFromDays(body.value.remember?.days));
					setFailure(void 0);
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				}
			}, []);
			React.useEffect(() => {
				refresh();
			}, [refresh]);
			const run = async (path, payload, done) => {
				setBusy(true);
				setFailure(void 0);
				setNotice(void 0);
				try {
					const body = await apiPost(path, payload);
					if (!body.ok) throw new Error(body.message ?? body.code ?? "request failed");
					syncTicket(body);
					setFirst("");
					setSecond("");
					setUnlockPw("");
					setOldPw("");
					await refresh();
					if (done !== void 0) setNotice(done);
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				} finally {
					setBusy(false);
				}
			};
			const saveSlider = async (raw) => {
				setBusy(true);
				setFailure(void 0);
				try {
					const body = await apiPost("/api/credentials.config", {
						action: "set",
						rememberDays: daysFromSlider(Number(raw))
					});
					if (!body.ok) throw new Error(body.message ?? body.code ?? "request failed");
					syncTicket(body);
					await refresh();
				} catch (error) {
					setFailure(error instanceof Error ? error.message : String(error));
				} finally {
					setBusy(false);
				}
			};
			const doublePassword = first.length > 0 && first === second && first.length >= 8;
			const passwordHint = first.length > 0 && first.length < 8 ? "密码至少 8 个字符" : first.length > 0 && second.length > 0 && first !== second ? "两次输入的密码不一致" : void 0;
			if (status === void 0) return React.createElement("p", { style: HINT }, "读取加密状态…");
			const { format, unlocked, local, remember, lockout } = status;
			const retryAfterMs = lockout?.retryAfterMs ?? 0;
			const lockSeconds = retryAfterMs > 0 ? Math.max(1, Math.ceil(retryAfterMs / 1e3)) : 0;
			const localBanner = !local ? React.createElement("p", {
				key: "nl",
				style: WARN
			}, "当前不是本机访问：必须每次输入密码解锁，且不能设置、修改或移除密码。") : null;
			const sliderCard = React.createElement("div", {
				key: "slider",
				style: CARD
			}, [
				React.createElement("p", {
					key: "t",
					style: LABEL
				}, "免密登录时长（仅本机生效）"),
				React.createElement("input", {
					key: "s",
					type: "range",
					min: 0,
					max: 31,
					step: 1,
					value: slider,
					disabled: busy || !local,
					onChange: (event) => setSlider(Number(event.currentTarget.value)),
					onPointerUp: (event) => void saveSlider(event.currentTarget.value),
					onKeyUp: (event) => {
						if ([
							"ArrowLeft",
							"ArrowRight",
							"Home",
							"End",
							"PageUp",
							"PageDown"
						].includes(event.key)) saveSlider(event.currentTarget.value);
					},
					style: {
						...SLIDER,
						opacity: !local ? .5 : 1
					}
				}),
				React.createElement("p", {
					key: "v",
					style: LABEL
				}, rememberLabel(slider)),
				React.createElement("div", {
					key: "m",
					style: SLIDER_MARKS
				}, [React.createElement("span", { key: "a" }, "每次"), React.createElement("span", { key: "e" }, "永远")]),
				!local ? React.createElement("p", {
					key: "n",
					style: HINT
				}, "非本机访问始终需要输入密码。") : remember?.active ? React.createElement("p", {
					key: "n",
					style: OK
				}, typeof remember.expiresAt === "number" ? `免密登录生效中，到期时间：${expiryText(remember.expiresAt)}` : "免密登录生效中，永不过期。") : React.createElement("p", {
					key: "n",
					style: HINT
				}, format === "plain" ? "设置加密密码后生效：按滑块时长在本机签发免密票据。" : "解锁后按滑块时长在本机签发免密票据。")
			]);
			if (format === "plain") return React.createElement("div", { style: ROW }, [
				localBanner,
				status.plaintextForbidden ? React.createElement("p", {
					key: "forbidden",
					style: WARN
				}, "警告：凭证文件被人替换成了明文，而密文策略已生效——凭证解析已暂停。请在下方重新设置加密密码，文件将立即恢复为密文。") : null,
				React.createElement("p", {
					key: "intro",
					style: LABEL
				}, "当前凭证以明文存储在 .credentials.yaml 中。设置密码后，同一文件的内容会被替换为 AES-256-GCM 密文（SHA3-256 完整性校验），每次模型调用时临时解密。"),
				local ? React.createElement("div", {
					key: "card",
					style: CARD
				}, [
					React.createElement("p", {
						key: "t",
						style: LABEL
					}, "设置加密密码"),
					React.createElement(Field, {
						key: "f1",
						placeholder: "新密码（至少 8 个字符）",
						value: first,
						disabled: busy,
						onChange: setFirst
					}),
					React.createElement(Field, {
						key: "f2",
						placeholder: "再次输入新密码",
						value: second,
						disabled: busy,
						onChange: setSecond
					}),
					passwordHint !== void 0 ? React.createElement("p", {
						key: "h",
						style: WARN
					}, passwordHint) : null,
					React.createElement(Button, {
						key: "b",
						disabled: busy || !doublePassword,
						onClick: () => void run("/api/credentials.set-password", { digest: sha3_256Hex(first) }, "密码已设置，凭证已加密保存")
					}, "加密并保存"),
					React.createElement("p", {
						key: "n",
						style: HINT
					}, "设置后重启 dsh 需要重新输入密码解锁（本设置页即是解锁入口）。忘记密码只能清除凭证重新配置。")
				]) : null,
				sliderCard,
				failure !== void 0 ? React.createElement("p", {
					key: "err",
					style: WARN
				}, failure) : null,
				notice !== void 0 ? React.createElement("p", {
					key: "ok",
					style: OK
				}, notice) : null
			]);
			if (!unlocked) return React.createElement("div", { style: ROW }, [
				localBanner,
				lockSeconds > 0 ? React.createElement("p", {
					key: "lockout",
					style: WARN
				}, `解锁尝试次数过多，已临时锁定：请在 ${lockSeconds} 秒后重试（连续失败会自动延长锁定时间）。`) : null,
				React.createElement("p", {
					key: "intro",
					style: WARN
				}, "凭证库已加密但处于锁定状态——模型调用暂时不可用。输入密码解锁后立即恢复。"),
				React.createElement("div", {
					key: "card",
					style: CARD
				}, [React.createElement(Field, {
					key: "f",
					placeholder: "凭证库密码",
					value: unlockPw,
					disabled: busy || lockSeconds > 0,
					onChange: setUnlockPw
				}), React.createElement(Button, {
					key: "b",
					disabled: busy || unlockPw.length === 0 || lockSeconds > 0,
					onClick: () => void run("/api/credentials.unlock", { digest: sha3_256Hex(unlockPw) }, "已解锁")
				}, "解锁")]),
				sliderCard,
				failure !== void 0 ? React.createElement("p", {
					key: "err",
					style: WARN
				}, failure) : null,
				notice !== void 0 ? React.createElement("p", {
					key: "ok",
					style: OK
				}, notice) : null
			]);
			return React.createElement("div", { style: ROW }, [
				localBanner,
				React.createElement("p", {
					key: "intro",
					style: OK
				}, "凭证已加密且当前进程已解锁。"),
				local ? React.createElement("div", {
					key: "card",
					style: CARD
				}, [
					React.createElement("p", {
						key: "t",
						style: LABEL
					}, "修改密码"),
					React.createElement(Field, {
						key: "f0",
						placeholder: "当前密码",
						value: oldPw,
						disabled: busy,
						onChange: setOldPw
					}),
					React.createElement(Field, {
						key: "f1",
						placeholder: "新密码（至少 8 个字符）",
						value: first,
						disabled: busy,
						onChange: setFirst
					}),
					React.createElement(Field, {
						key: "f2",
						placeholder: "再次输入新密码",
						value: second,
						disabled: busy,
						onChange: setSecond
					}),
					passwordHint !== void 0 ? React.createElement("p", {
						key: "h",
						style: WARN
					}, passwordHint) : null,
					React.createElement(Button, {
						key: "b",
						disabled: busy || !doublePassword || oldPw.length === 0,
						onClick: () => void run("/api/credentials.change-password", {
							digest: sha3_256Hex(first),
							oldDigest: sha3_256Hex(oldPw)
						}, "密码已修改")
					}, "修改密码")
				]) : null,
				sliderCard,
				failure !== void 0 ? React.createElement("p", {
					key: "err",
					style: WARN
				}, failure) : null,
				notice !== void 0 ? React.createElement("p", {
					key: "ok",
					style: OK
				}, notice) : null
			]);
		}
		const inject = ["slots"];
		function apply(ctx) {
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "encryption",
				order: 1,
				label: () => "加密安全"
			}, EncryptionSection));
		}
		exports.apply = apply;
		exports.inject = inject;
		exports.digestPassword = sha3_256Hex;
		return module.exports;
	}
});
//#endregion
export {};

//# sourceMappingURL=client.js.map