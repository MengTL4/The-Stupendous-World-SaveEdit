import { useEffect, useMemo, useRef, useState } from "react";
import JSONEditor, { type JSONEditorOptions } from "jsoneditor";
import "jsoneditor/dist/jsoneditor.css";
import {
  decodeSaveText,
  encodeSaveText,
  fromJsonFriendly,
  toJsonFriendly,
  type SaveTextParts,
} from "./codec";

function createDownload(content: string, filename: string): void {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function stripExt(filename: string): string {
  const dot = filename.lastIndexOf(".");
  if (dot <= 0) {
    return filename;
  }
  return filename.slice(0, dot);
}

function App() {
  const [saveInput, setSaveInput] = useState("");
  const [saveOutput, setSaveOutput] = useState("");
  const [status, setStatus] = useState("就绪，可加载存档。");
  const [error, setError] = useState<string | null>(null);
  const [preserveAffix, setPreserveAffix] = useState(true);
  const [lastSaveName, setLastSaveName] = useState("file1.rpgsave");
  const [lastJsonName, setLastJsonName] = useState("file1.json");
  const [parts, setParts] = useState<SaveTextParts | null>(null);

  const saveFileInputRef = useRef<HTMLInputElement | null>(null);
  const jsonFileInputRef = useRef<HTMLInputElement | null>(null);
  const editorHostRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<JSONEditor | null>(null);

  const outputSaveName = useMemo(() => `${stripExt(lastSaveName)}.rebuilt.rpgsave`, [lastSaveName]);
  const outputJsonName = useMemo(() => `${stripExt(lastSaveName)}.json`, [lastSaveName]);

  useEffect(() => {
    if (!editorHostRef.current) {
      return;
    }

    const options: JSONEditorOptions = {
      mode: "tree",
      modes: ["tree", "view", "form", "code", "text"],
      language: "zh-CN",
      mainMenuBar: true,
      navigationBar: true,
      statusBar: true,
      onError: (errorValue: Error) => {
        setError(`编辑器错误：${errorValue.message}`);
      },
    };

    const editor = new JSONEditor(editorHostRef.current, options, {});
    editorRef.current = editor;
    setStatus("编辑器已就绪，可解密并编辑 JSON（支持节点展开/收缩）。");

    return () => {
      editor.destroy();
      editorRef.current = null;
    };
  }, []);

  const setEditorValue = (value: unknown): void => {
    if (!editorRef.current) {
      throw new Error("JSON 编辑器尚未初始化。请稍等页面加载完成。");
    }
    editorRef.current.set(value as never);
  };

  const getEditorValue = (): unknown => {
    if (!editorRef.current) {
      throw new Error("JSON 编辑器尚未初始化。请稍等页面加载完成。");
    }
    return editorRef.current.get();
  };

  const handleSaveFileLoad = async (event: React.ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    const text = await file.text();
    setSaveInput(text);
    setLastSaveName(file.name);
    setStatus(`已加载存档文本：${file.name}（${text.length.toLocaleString()} 字符）`);
    setError(null);
    event.target.value = "";
  };

  const handleJsonFileLoad = async (event: React.ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as unknown;
      setEditorValue(parsed);
      setLastJsonName(file.name);
      setStatus(`已加载 JSON：${file.name}（${text.length.toLocaleString()} 字符）`);
      setError(null);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(`载入 JSON 失败：${message}`);
      setStatus("载入 JSON 失败。");
    }
    event.target.value = "";
  };

  const handleDecode = (): void => {
    setError(null);
    try {
      const decoded = decodeSaveText(saveInput);
      const friendly = toJsonFriendly(decoded.value);
      setEditorValue(friendly);
      setParts(decoded.parts);
      setLastJsonName(outputJsonName);
      setStatus(
        `解密成功：payload ${decoded.parts.payload.length.toLocaleString()} 字符，` +
          `前缀 ${decoded.parts.prefix.length} 字符，后缀 ${decoded.parts.suffix.length} 字符。`
      );
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(`解密失败：${message}`);
      setStatus("解密失败。");
    }
  };

  const handleEncode = (): void => {
    setError(null);
    try {
      const editorValue = getEditorValue();
      const restored = fromJsonFriendly(editorValue);
      const encoded = encodeSaveText(restored, preserveAffix && parts ? parts : undefined);
      setSaveOutput(encoded);
      setStatus(`加密成功：输出 ${encoded.length.toLocaleString()} 字符。`);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(`加密失败：${message}`);
      setStatus("加密失败。");
    }
  };

  const handleFormatJson = (): void => {
    setError(null);
    try {
      const parsed = getEditorValue();
      setEditorValue(parsed);
      setStatus("JSON 已规范化。");
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(`格式化失败：${message}`);
      setStatus("格式化失败。");
    }
  };

  const handleValidateJson = (): void => {
    setError(null);
    try {
      const parsed = getEditorValue();
      fromJsonFriendly(parsed);
      setStatus("JSON 校验通过，标记字段可正常解析。");
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(`校验失败：${message}`);
      setStatus("校验失败。");
    }
  };

  const handleExpandAll = (): void => {
    if (!editorRef.current) {
      return;
    }
    editorRef.current.expandAll();
    setStatus("已展开全部节点。");
  };

  const handleCollapseAll = (): void => {
    if (!editorRef.current) {
      return;
    }
    editorRef.current.collapseAll();
    setStatus("已收起全部节点。");
  };

  return (
    <div className="app">
      <header className="header">
        <h1>RPG 存档加解密 + JSON 树形编辑器</h1>
        <p>
          支持格式：<code>base64 -&gt; zlib -&gt; MessagePack</code>。JSON 编辑区支持节点逐级展开/收缩，适合处理大体积数据。
          标记对象 <code>$binary</code>、<code>$ext</code>、<code>$map</code>、<code>$bigint</code> 可安全往返。
        </p>
      </header>

      <section className="toolbar">
        <button onClick={() => saveFileInputRef.current?.click()}>加载存档文件</button>
        <button onClick={() => jsonFileInputRef.current?.click()}>加载 JSON 文件</button>
        <button onClick={handleDecode}>解密存档 -&gt; JSON</button>
        <button onClick={handleEncode}>加密 JSON -&gt; 存档</button>
        <button onClick={handleValidateJson}>校验 JSON</button>
        <button onClick={handleFormatJson}>规范化 JSON</button>
        <button onClick={handleExpandAll}>展开全部</button>
        <button onClick={handleCollapseAll}>收起全部</button>
        <button
          onClick={() => {
            try {
              const value = JSON.stringify(getEditorValue(), null, 2);
              createDownload(value, lastJsonName || outputJsonName);
            } catch (cause) {
              const message = cause instanceof Error ? cause.message : String(cause);
              setError(`导出 JSON 失败：${message}`);
            }
          }}
        >
          下载 JSON
        </button>
        <button
          onClick={() => {
            if (!saveOutput.trim()) {
              setError("无法下载存档：加密输出为空。");
              return;
            }
            createDownload(saveOutput, outputSaveName);
          }}
        >
          下载存档
        </button>

        <label className="toggle">
          <input
            type="checkbox"
            checked={preserveAffix}
            onChange={(event) => setPreserveAffix(event.target.checked)}
          />
          保留源存档前后缀
        </label>

        <input
          ref={saveFileInputRef}
          type="file"
          accept=".rpgsave,.txt"
          className="hidden"
          onChange={handleSaveFileLoad}
        />
        <input
          ref={jsonFileInputRef}
          type="file"
          accept=".json"
          className="hidden"
          onChange={handleJsonFileLoad}
        />
      </section>

      <section className="status">
        <div>
          <strong>状态：</strong> {status}
        </div>
        {parts && (
          <div>
            <strong>检测到前后缀：</strong> 前缀 {parts.prefix.length} 字符，后缀 {parts.suffix.length} 字符
          </div>
        )}
        {error && <div className="error">{error}</div>}
      </section>

      <section className="io-grid">
        <div className="panel">
          <h2>加密存档输入</h2>
          <textarea
            value={saveInput}
            onChange={(event) => setSaveInput(event.target.value)}
            placeholder="在此粘贴 .rpgsave 文本（或点击按钮加载文件）"
          />
        </div>

        <div className="panel">
          <h2>加密存档输出</h2>
          <textarea
            value={saveOutput}
            onChange={(event) => setSaveOutput(event.target.value)}
            placeholder="执行“加密 JSON -&gt; 存档”后，结果会显示在这里"
          />
        </div>
      </section>

      <section className="editor-panel">
        <h2>解密 JSON 编辑区（树形，可逐节点展开/收缩）</h2>
        <div className="jsoneditor-host" ref={editorHostRef} />
      </section>
    </div>
  );
}

export default App;
