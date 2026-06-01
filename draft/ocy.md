# 15 分鐘講稿：Software Supply Chain Attacks — From Attacks to Prevention 之前

各位好，我們今天要報告的主題是 **Software Supply Chain Attacks**，也就是軟體供應鏈攻擊。這次我們特別聚焦在 **Build Provenance**，也就是「建置來源證明」這個概念。

在進入技術細節以前，我想先從一個很日常的情境開始。
如果你是開發者，你每天可能都會執行這些指令：

`npm install`、`pip install`、`mvn install`、`conda install`

這些指令看起來很普通，甚至已經變成開發流程的一部分。可是它們背後其實代表一件事：我們正在下載並執行第三方程式碼。更重要的是，一個 dependency 可能又會拉進很多 transitive dependencies，也就是間接相依套件。所以我們以為自己只安裝了一個套件，但實際上可能引入了幾十個、甚至上百個外部 package。

問題是：我們真的有檢查這些 package 沒有被竄改嗎？
大多數時候，其實沒有。我們相信 package manager、相信 registry、相信 maintainer，也相信 CI/CD pipeline。這種信任本身，就是軟體供應鏈攻擊會成功的原因。

---

接下來先定義什麼是 **Software Supply Chain**。

根據 NIST 的說法，Software Supply Chain 是一連串建立、轉換、評估軟體 artifact 品質與政策符合性的步驟。換成比較直覺的說法，它不只是我們自己寫的 source code，而是包含整個軟體開發和發布流程。

這裡面包括 source code、第三方 dependencies、version control system、build tools、CI/CD pipeline、package registry，以及最後發布出去的 software artifact。

所以，**software supply chain attack** 指的是攻擊者不是直接攻擊最後的 application，而是去攻擊這條鏈上的某一個可信任環節。
例如攻擊 dependency、maintainer account、build cache、CI workflow，或者 package registry。

這種攻擊很危險，因為它利用的是開發流程裡的信任關係。
開發者相信套件，package manager 相信 registry，CI/CD 相信 workflow，使用者相信發布出來的 artifact。只要其中一個環節被攻擊，惡意程式碼就可能透過正常流程被散布出去。

而且 open-source package 的影響範圍通常很大。一個熱門 package 可能被很多下游專案使用，所以一次 compromise 可能不只影響一個專案，而是影響整個 ecosystem。

---

接下來看幾種常見的供應鏈攻擊形式。

第一種是 **Typosquatting**。
這是攻擊者發布一個名稱很像熱門套件的惡意 package。例如原本應該安裝 `requests`，但攻擊者創造一個拼字很接近的套件，讓開發者不小心裝錯。這種攻擊利用的是人的疏忽。

第二種是 **Dependency Confusion**。
這種攻擊會利用 public registry 和 private registry 的解析順序。如果公司內部使用一個 private package，但 public registry 上出現同名 package，而且版本號更高，package manager 可能會下載錯誤的 public package。這樣攻擊者就能把惡意 package 混進企業環境。

第三種是 **Account Takeover**。
攻擊者偷到 maintainer 的帳號或 token，然後直接發布惡意版本。這種情況特別危險，因為 package name 沒有變，maintainer 也看起來是原本的人，所以一般使用者很難察覺。

第四種是 **Package Takeover**。
有些 package 長期沒有人維護，攻擊者可能透過社交工程或其他方式取得維護權。取得 ownership 之後，就可以發布新的惡意版本。

第五種是 **Code Injection**。
這是直接把惡意程式碼塞進 trusted package 或 dependency 裡面。惡意程式碼可能藏在 install script、build script，或者看起來很普通的 source code 裡。

第六種是 **CI/CD Compromise**。
攻擊者不是攻擊 source code，而是攻擊 build workflow、cache、token 或 release pipeline。這種攻擊很棘手，因為 source code 可能看起來是乾淨的，但是 build 出來的 artifact 已經被污染。

這些攻擊形式說明一件事：供應鏈安全不是只保護 source code 就夠了。我們還需要保護 packages、maintainers、registries、build pipeline，以及發布流程中的每個可信任環節。

---

那為什麼 software supply chain 會變成 top risk？

在 OWASP Top 10:2025 裡，**Software Supply Chain Failures** 被列為 A03。這代表現代軟體風險正在改變。以前我們比較常關注 SQL injection、XSS、broken authentication 這種 application-level vulnerability。可是現在，軟體系統越來越依賴第三方 components，package managers 會自動解析 transitive dependencies，CI/CD pipeline 會自動 build 和 publish artifact。

也就是說，現在一個 application 的安全性，不只取決於我們自己寫得好不好，也取決於上游 dependency、build system、maintainer account 和 registry 是否可信。

如果一個上游 component 被 compromise，很多 downstream users 都可能受到影響。這也是為什麼供應鏈安全變成高風險議題。

---

不過這裡也要注意 OWASP ranking 的意義。

OWASP Top 10:2025 是 **data-informed**，不是完全 data-driven。
也就是說，它不是單純根據某一個統計數字排序，而是結合 contributed testing data、CVE-based exploit and impact scores，以及 community survey results。

以 A03:2025 Software Supply Chain Failures 來說，OWASP 提到幾個數字。

第一個是 **Avg Incidence Rate: 5.72%**。
這代表在 OWASP 收到的測試資料裡，被 mapping 到 A03 的 CWE 平均發生率。

第二個是 **Total Occurrences: 215,248**。
這表示測試資料中，有這麼多 application 被發現有對應到 A03 類別的 CWE。

第三個是 **Total CVEs: 11**。
這表示 NVD 裡有 11 個 CVE 被 mapping 到 A03 類別的 CWE。

但這些數字不能被誤解成全球攻擊頻率。它們反映的是現有 testing tools 和 contributors 能夠觀察到、能夠回報的資料。供應鏈攻擊很多時候很難偵測，也不一定會被記錄成 CVE，所以實際風險可能被低估。

這點很重要，因為 supply chain security 的難處之一，就是很多攻擊不是傳統漏洞掃描能直接抓到的。

---

接下來談經濟影響。

Software supply chain attacks 的財務損失其實很難直接衡量，因為很多 incident 不會公開完整損失。有些公司只會說已經處理完成，不會揭露停機時間、credential rotation 成本、legal risk 或 reputational damage。

但是從 breach-cost data 來看，供應鏈 compromise 的成本確實很高。
根據 IBM 2025 的資料，third-party vendor 和 supply chain compromise 平均每次攻擊成本約為 **4.91 million USD**。而且它是第二常見、也是第二昂貴的 data breach vector。

這些成本不只是修 bug。它包括 incident response、系統停機、重建 CI/CD pipeline、更換 credentials、重新簽署或撤銷 certificates、法律風險，以及客戶對公司的信任損失。

另外，ReversingLabs 2026 也提到，2025 年 malicious open-source package detections 增加了 **73%**，其中 npm 佔了將近 **90%** 的 detected OSS malware。

這些數字說明，open-source package ecosystem 已經成為攻擊者很重視的目標。

---

為什麼 open-source package risk 會持續增加？

原因是 modern package ecosystems 有幾個特性。

第一，安裝是自動化的。
開發者通常不會逐行檢查 dependency source code，而是直接讓 package manager 下載。

第二，信任是隱性的。
當我們安裝一個 package 時，我們其實同時信任 maintainer、registry、package metadata、dependency tree，以及 install script。

第三，dependency graph 很深。
即使你直接依賴的 package 是安全的，它的 transitive dependency 仍然可能有風險。

第四，npm ecosystem 特別大，而且 JavaScript package 常常有很多小型依賴。這讓攻擊者只要 compromise 一個 package，就可能影響非常多專案。

所以我們把焦點放在 npm-style supply chain risk 是合理的，因為它具有大規模、自動化、高傳遞性的特徵。

---

到這裡，我們已經看到攻擊面很廣，風險也不只是理論問題。接下來就要從攻擊轉向防禦，也就是 **From Attacks to Prevention**。

這裡我們引入一個重要框架：**SLSA**，全名是 Supply-chain Levels for Software Artifacts。

SLSA 是一個 software supply chain security framework，目標是防止 tampering、提升 artifact integrity，並保護 packages 和 build infrastructure。

但是防禦不能只看單一工具。實務上，我們可以把 prevention strategy 分成四層。

第一層是 **Dependency layer**。
這一層的重點是管理相依套件。常見方法包括 lockfiles、SBOM，以及 vulnerability scanning。
Lockfile 可以固定 dependency version 和 hash，SBOM 可以列出軟體裡用了哪些 components，vulnerability scanner 可以檢查已知 CVE。

第二層是 **Source layer**。
這一層保護 source code repository。方法包括 protected branches、code review，以及 MFA。
因為如果 source repo 被攻擊，後面的 build provenance 再完整，也只是證明惡意程式碼確實來自被攻擊後的 source。

第三層是 **Build layer**。
這一層是我們今天之後會特別關注的部分。它包括 isolated builds、cache control，以及 provenance。
Build 系統需要避免被污染，因為攻擊者可以不改 source code，而是在 build 過程中注入惡意內容。

第四層是 **Release layer**。
這一層保護 artifact 發布。方法包括 signed artifacts、registry attestations，以及 install-time verification。
也就是說，使用者在安裝 package 之前，應該能驗證這個 package 是不是由正確的 workflow、正確的 source commit build 出來的。

這裡有一個很重要的觀念：
**Build provenance 很重要，但它不是萬能。**

Build provenance 可以告訴我們：這個 artifact 是從哪個 commit、由哪個 pipeline、在什麼時間 build 出來的。
但是如果 CI/CD workflow 本身被攻擊，那 provenance 仍然可能看起來是 valid 的。也就是說，它可以證明「這是從某個流程產生的」，但不一定能證明「這個流程是乾淨的」。

所以我們的核心立場是：
Build provenance 是 supply chain security 裡非常重要的一部分，但它必須搭配 dependency management、source protection、CI/CD hardening 和 install-time verification，才能形成比較完整的防禦。

---

總結到目前為止，software supply chain attack 的本質是攻擊信任鏈。
它不一定攻擊 application 本身，而是攻擊 dependency、maintainer、registry、build pipeline 或 release process。

而現代開發流程高度依賴自動化與第三方 components，這使得一次上游 compromise 可能快速擴散到大量 downstream users。

因此，接下來我們會進一步看實際案例，包含 axios 和 TanStack，並討論 build provenance 如何幫助防禦，以及它在真實攻擊中仍然有哪些限制。
