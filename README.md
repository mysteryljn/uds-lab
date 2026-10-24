# uds-lab

一个纯软件 UDS（ISO 14229）练习和回归测试实验室。它模拟常用服务的正负响应，不连接 ECU、不依赖 CAN 适配器，可用于诊断脚本和协议边界测试。

覆盖 DiagnosticSessionControl 0x10、TesterPresent 0x3E、ReadDataByIdentifier 0x22、SecurityAccess 0x27 和 ReadDTCInformation 0x19。使用示例：python udslab.py 10 03。

诊断行为经常分散在 CDD、脚本和台架配置中，复现边界条件需要完整环境。这个状态机可以在本地先固化协议期望。安全访问算法只是教学用例，不能用于量产 ECU。

## 许可证

MIT
