# npm Supply Chain Risk Gate

這是一個很簡單的 npm supply chain demo scanner。

重點：

- 固定掃描 `examples/demo-project`
- 固定輸出到 `results`
- 主要讀 `package-lock.json`
- scanner 本身不執行 `npm install`
- 檢查 GitHub dependency、install script、npm audit、OSV

## 這版在示範什麼

`examples/demo-project/package.json` 會引用：

```json
"demo-malicious-tool": "github:OuChiaYun/demo-malicious-tool#main"
```

這代表 victim app 不是吃本機套件，而是從 GitHub 抓 dependency。

`package-lock.json` 會記錄這個套件：

```json
"hasInstallScript": true
```

所以 scanner 會標出：

- 這是 GitHub dependency
- 它有 install script
- 如果真的執行 `npm install`，安裝階段可能自動執行 `postinstall`

## 使用方式

```bash
chmod +x run.sh clean.sh
./run.sh
```

看結果：

```text
results/report.html
results/report.json
results/raw/
```

清除結果：

```bash
./clean.sh
```

## 如果你想真的觀察 postinstall demo

scanner 不會執行 `npm install`，因為它是防禦端工具。

如果你要在測試環境親眼看到 GitHub dependency 的 postinstall 被觸發，可以進去 demo project 後自己跑：

```bash
cd examples/demo-project
rm -rf node_modules
npm install
```

這只適合對你自己建立的 security demo repo 使用，不要拿未知套件亂測。
