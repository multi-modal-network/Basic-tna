// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.basic.tna.behaviour;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.primitives.UnsignedInteger;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IP;
import org.onlab.packet.IPacket;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Map;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.json.JSONObject;
import org.json.JSONArray;

import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.PortNumber.TABLE;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter.mapTable0Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter1.mapTable1Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter2.mapTable2Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter3.mapTable3Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter4.mapTable4Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter5.mapTable5Treatment;

/**
 * Interpreter for fabric-tna pipeline.
 */
public class BasicInterpreter extends AbstractBasicHandlerBehavior
        implements PiPipelineInterpreter {
    private static final Logger log = getLogger(BasicInterpreter.class);
    private static final Set<PiTableId> TABLE0_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.BASIC_INGRESS_TABLE0_TABLE0,
            P4InfoConstants.BASIC_INGRESS_TABLE1_TABLE1,
            P4InfoConstants.BASIC_INGRESS_TABLE2_TABLE2,
            P4InfoConstants.BASIC_INGRESS_TABLE3_TABLE3,
            P4InfoConstants.BASIC_INGRESS_TABLE4_TABLE4,
            P4InfoConstants.BASIC_INGRESS_TABLE5_TABLE5);
    private static final Map<Integer, PiTableId> TABLE_MAP =
            new ImmutableMap.Builder<Integer, PiTableId>()
                    .put(0, P4InfoConstants.BASIC_INGRESS_TABLE0_TABLE0)
                    .put(1, P4InfoConstants.BASIC_INGRESS_TABLE1_TABLE1)
                    .put(2, P4InfoConstants.BASIC_INGRESS_TABLE2_TABLE2)
                    .put(3, P4InfoConstants.BASIC_INGRESS_TABLE3_TABLE3)
                    .put(4, P4InfoConstants.BASIC_INGRESS_TABLE4_TABLE4)
                    .put(5, P4InfoConstants.BASIC_INGRESS_TABLE5_TABLE5)
                    .build();
    private static final ImmutableMap<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            ImmutableMap.<Criterion.Type, PiMatchFieldId>builder()
                    .put(Criterion.Type.IN_PORT, P4InfoConstants.HDR_IG_PORT)
                    .put(Criterion.Type.ETH_DST, P4InfoConstants.HDR_ETH_DST)
                    .put(Criterion.Type.ETH_SRC, P4InfoConstants.HDR_ETH_SRC)
                    .put(Criterion.Type.ETH_TYPE, P4InfoConstants.HDR_ETH_TYPE)
                    .put(Criterion.Type.IPV4_DST, P4InfoConstants.HDR_IPV4_DST)
                    .put(Criterion.Type.IPV4_SRC, P4InfoConstants.HDR_IPV4_SRC)
                    .put(Criterion.Type.IP_PROTO, P4InfoConstants.HDR_IP_PROTO)
                    .put(Criterion.Type.UDP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.UDP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .put(Criterion.Type.TCP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.TCP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .build();

    private BasicTreatmentInterpreter treatmentInterpreter;

    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    public BasicInterpreter(BasicCapabilities capabilities) {
        super(capabilities);
        instantiateTreatmentInterpreter();
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public BasicInterpreter() {
        super();
    }

    private void instantiateTreatmentInterpreter() {
        this.treatmentInterpreter = new BasicTreatmentInterpreter(this.capabilities);
    }

    @Override
    public void setHandler(DriverHandler handler) {
        super.setHandler(handler);
        instantiateTreatmentInterpreter();
    }

    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        // The only use case for Index ID->PiTableId is when using the single
        // table pipeliner. fabric.p4 is never used with such pipeliner.
        return Optional.ofNullable(TABLE_MAP.get(flowRuleTableId));
    }

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
            throws PiInterpreterException {
        if (TABLE0_CTRL_TBLS.contains(piTableId)) {
            return mapTable0Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.BASIC_INGRESS_TABLE1_TABLE1)) {
            return mapTable1Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.BASIC_INGRESS_TABLE2_TABLE2)) {
            return mapTable2Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.BASIC_INGRESS_TABLE3_TABLE3)) {
            return mapTable3Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.BASIC_INGRESS_TABLE4_TABLE4)) {
            return mapTable4Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.BASIC_INGRESS_TABLE5_TABLE5)) {
            return mapTable5Treatment(treatment, piTableId);
        } else {
            throw new PiInterpreterException(format(
                    "Treatment mapping not supported for table '%s'", piTableId));
        }
    }

    private PiPacketOperation createPiPacketOperation(
            ByteBuffer data, long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        Collection<PiPacketMetadata> metadata = createPacketMetadata(portNumber, doForwarding);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(metadata)
                .build();
    }

    private Collection<PiPacketMetadata> createPacketMetadata(
            long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        try {
            ImmutableList.Builder<PiPacketMetadata> builder = ImmutableList.builder();
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD0)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD0_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.EGRESS_PORT)
                    .withValue(copyFrom(portNumber)
                            .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                    .build());

            return builder.build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number '%d' too big, %s", portNumber, e.getMessage()));
        }
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
            throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // We support only OUTPUT instructions.
        List<Instructions.OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (Instructions.OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (Instructions.OutputInstruction outInst : outInstructions) {
            if (outInst.port().equals(TABLE)) {
                // Logical port. Forward using the switch tables like a regular packet.
                builder.add(createPiPacketOperation(packet.data(), 0, true));
            } else if (outInst.port().equals(FLOOD)) {
                // Logical port. Create a packet operation for each switch port.
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(createPiPacketOperation(packet.data(), port.number().toLong(), false));
                }
            } else if (outInst.port().isLogical()) {
                throw new PiInterpreterException(format(
                        "Output on logical port '%s' not supported", outInst.port()));
            } else {
                // Send as-is to given port bypassing all switch tables.
                builder.add(createPiPacketOperation(packet.data(), outInst.port().toLong(), false));
            }
        }
        return builder.build();
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId) throws PiInterpreterException {
        // Assuming that the packet is ethernet, which is fine since fabric.p4
        // can deparse only ethernet packets.
        Ethernet ethPkt;
        log.warn("new Pkt");
        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0,
                                                         packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadata = packetIn.metadatas()
                .stream().filter(m -> m.id().equals(P4InfoConstants.INGRESS_PORT))
                .findFirst();
        final int pktType;

        if (packetMetadata.isPresent()) {
            try {
                ImmutableByteSequence portByteSequence = packetMetadata.get()
                        .value().fit(P4InfoConstants.INGRESS_PORT_BITWIDTH);
                UnsignedInteger ui =
                    UnsignedInteger.fromIntBits(portByteSequence.asReadOnlyBuffer().getInt());
                ConnectPoint receivedFrom =
                    new ConnectPoint(deviceId, PortNumber.portNumber(ui.longValue()));
                if (!receivedFrom.port().hasName()) {
                    receivedFrom = translateSwitchPort(receivedFrom);
                }
                ByteBuffer rawData = ByteBuffer.wrap(packetIn.data().asArray());
                pktType = ethPkt.getEtherType();
                log.warn("new Pkt is {} type from device {} port {}",pktType,deviceId,portByteSequence);
                byte[] payload = ethPkt.getPayload().serialize();
                log.warn("payLoad Length {} : {}",payload.length,payload);
                log.warn("Packet: {}", ethPkt);
                // 解析模态、计算路径、下发流表
                handleModalPacket(pktType, ethPkt.getPayload().serialize());
                // 解析各种模态
                // parserPkt(pktType,payload);
                // sendToMMQueue(ethPkt);

                // 构造PakcetOut数据包发回原始数据
//                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
//                        .setOutput(receivedFrom.port()).build();
//                DefaultOutboundPacket outPakcet = new DefaultOutboundPacket(deviceId,treatment,rawData);
//                log.warn("Send Packet: {}",outPakcet);
//                mapOutboundPacket(outPakcet).forEach(op-> packetOut);



                return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
            } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
                throw new PiInterpreterException(format(
                        "Malformed metadata '%s' in packet-in received from '%s': %s",
                        P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
            }
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
        }
    }

    // public void sendToMMQueue(Ethernet ethPkt) throws ClientException {
    //     String endpoint = "localhost:8081";
    //     String topic = "TestTopic";
    //     ClientServiceProvider provider = ClientServiceProvider.loadService();
    //     ClientConfigurationBuilder builder = ClientConfiguration.newBuilder().setEndpoints(endpoint);
    //     ClientConfiguration configuration = builder.build();
    //     Producer producer = provider.newProducerBuilder()
    //         .setTopics(topic)
    //         .setClientConfiguration(configuration)
    //         .build();
    //     // 普通消息发送。
    //     Message message = provider.newMessageBuilder()
    //         .setTopic(topic)
    //         // 设置消息索引键，可根据关键字精确查找某条消息。
    //         .setKeys(String.format("%d",ethPkt.getEtherType()))
    //         // 设置消息Tag，用于消费端根据指定Tag过滤消息。
    //         .setTag("messageTag")
    //         // 消息体。
    //         .setBody("test modal packet".getBytes())
    //         .build();
    //     try {
    //         // 发送消息，需要关注发送结果，并捕获失败等异常。
    //         SendReceipt sendReceipt = producer.send(message);
    //         log.info("Send message successfully, messageId={}", sendReceipt.getMessageId());
    //     } catch (ClientException e) {
    //         log.error("Failed to send message", e);
    //     }
    //     // producer.close();
    // }

    public int vmx = 1;

    private String decimal2Hex(int value, int length) {
        String hexNumber = Integer.toHexString(value).toUpperCase();
        if(length == 8) {
            return String.format("%8s", hexNumber).replace(' ','0');
        }
        return String.format("%4s", hexNumber).replace(' ','0');
    }

    private String ip2Hex(String ipAddr) {
        String[] parts = ipAddr.split("\\.");
        String hexAddr = "";
        for(int i=0;i<parts.length;i++) {
            int part = Integer.parseInt(parts[i]);
            String hexPart = Integer.toHexString(part).toUpperCase();
            hexAddr = hexAddr + String.format("%2s", hexPart).replace(' ','0');
        }
        return hexAddr;
    }

    public JSONObject generateIPFlows(int switchID, int port, int srcIdentifier, int dstIdentifier) {
        String srcIP = String.format("172.20.%s.%s", vmx+1, srcIdentifier-64+12);
        String dstIP = String.format("172.20.%s.%s", vmx+1, dstIdentifier-64+12);
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        log.warn("generateIPFlows srcIdentifier:{}, dstIdentifier:{}, srcIP:{}, dstIP:{}",
                srcIdentifier, dstIdentifier, srcIP, dstIP);
        String deviceID = String.format("device:domain1:group4:level%d:s%d",level, switchID + 300);
        JSONObject flowObject = new JSONObject();
        flowObject.put("priority", 10);
        flowObject.put("timeout", 0);
        flowObject.put("isPermanent", "true");
        flowObject.put("tableId",1);                // ip的tableId=1
        flowObject.put("deviceId", deviceID);
        flowObject.put("treatment", new JSONObject()
                .put("instructions", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("subtype", "ACTION")
                                .put("actionId", "ingress.set_next_v4_hop")
                                .put("actionParams", new JSONObject()
                                        .put("dst_port", String.format("%s", port))))));
        flowObject.put("clearDeferred", "true");
        flowObject.put("selector", new JSONObject()
                .put("criteria", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("matches", new JSONArray()
                                        .put(new JSONObject()
                                                .put("field", "hdr.ethernet.ether_type")
                                                .put("match", "exact")
                                                .put("value", "0800"))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ipv4.srcAddr")
                                                .put("match", "exact")
                                                .put("value", ip2Hex(srcIP)))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ipv4.dstAddr")
                                                .put("match", "exact")
                                                .put("value", ip2Hex(dstIP)))))));
        return new JSONObject().put("flows", new JSONArray().put(flowObject));
    }

    public JSONObject generateIDFlows(int switchID, int port, int srcIdentifier, int dstIdentifier) {
        /*
        {
            "flows": [
                {
                    "priority": 10,
                    "timeout": 0,
                    "isPermanent": "true",
                    "tableId": "5",     // id的tableId=5
                    "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
                    "treatment": {
                        "instructions": [
                            {
                                "type": "PROTOCOL_INDEPENDENT",
                                "subtype": "ACTION",
                                "actionId": "ingress.set_next_id_hop",
                                "actionParams": {
                                    "dst_port": f"{port}"
                                }
                            }
                        ]
                    },
                    "clearDeferred": "true",
                    "selector": {
                        "criteria": [
                            {
                                "type": "PROTOCOL_INDEPENDENT",
                                "matches": [
                                    {
                                        "field": "hdr.ethernet.ether_type",
                                        "match": "exact",
                                        "value": "0812"
                                    },
                                    {
                                        "field": "hdr.id.srcIdentity",
                                        "match": "exact",
                                        "value": decimal_to_8hex(identity_src)
                                    },
                                    {
                                        "field": "hdr.id.dstIdentity",
                                        "match": "exact",
                                        "value": decimal_to_8hex(identity_dst)
                                    },
                                ]
                            }
                        ]
                    }
                }
            ]
        }
         */
        int srcIdentity = 202271720 + vmx * 100000 + srcIdentifier - 64;
        int dstIdentity = 202271720 + vmx * 100000 + dstIdentifier - 64;
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        log.warn("generateIDFlows srcIdentifier:{}, dstIdentifier:{}, srcIdentity:{}, dstIdentity:{}",
                srcIdentifier, dstIdentifier, srcIdentity, dstIdentity);
        String deviceID = String.format("device:domain1:group4:level%d:s%d",level, switchID + 300);
        JSONObject flowObject = new JSONObject();
        flowObject.put("priority", 10);
        flowObject.put("timeout", 0);
        flowObject.put("isPermanent", "true");
        flowObject.put("tableId",5);                // id的tableId=5
        flowObject.put("deviceId", deviceID);
        flowObject.put("treatment", new JSONObject()
                .put("instructions", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("subtype", "ACTION")
                                .put("actionId", "ingress.set_next_id_hop")
                                .put("actionParams", new JSONObject()
                                        .put("dst_port", String.format("%s", port))))));
        flowObject.put("clearDeferred", "true");
        flowObject.put("selector", new JSONObject()
                .put("criteria", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("matches", new JSONArray()
                                        .put(new JSONObject()
                                                .put("field", "hdr.ethernet.ether_type")
                                                .put("match", "exact")
                                                .put("value", "0812"))
                                        .put(new JSONObject()
                                                .put("field", "hdr.id.srcIdentity")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(srcIdentity,8)))
                                        .put(new JSONObject()
                                                .put("field", "hdr.id.dstIdentity")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(dstIdentity,8)))))));
        return new JSONObject().put("flows", new JSONArray().put(flowObject));
    }

    public JSONObject generateMFFlows(int switchID, int port, int srcIdentifier, int dstIdentifier) {
        int srcMFGuid = 1 + vmx * 100 + srcIdentifier - 64;
        int dstMFGuid = 1 + vmx * 100 + dstIdentifier - 64;
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        log.warn("generateMFFlows srcIdentifier:{}, dstIdentifier:{}, srcMFGuid:{}, dstMFGuid:{}",
                srcIdentifier, dstIdentifier, srcMFGuid, dstMFGuid);
        String deviceID = String.format("device:domain1:group4:level%d:s%d",level, switchID + 300);
        JSONObject flowObject = new JSONObject();
        flowObject.put("priority", 10);
        flowObject.put("timeout", 0);
        flowObject.put("isPermanent", "true");
        flowObject.put("tableId",2);                // mf的tableId=4
        flowObject.put("deviceId", deviceID);
        flowObject.put("treatment", new JSONObject()
                .put("instructions", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("subtype", "ACTION")
                                .put("actionId", "ingress.set_next_mf_hop")
                                .put("actionParams", new JSONObject()
                                        .put("dst_port", String.format("%s", port))))));
        flowObject.put("clearDeferred", "true");
        flowObject.put("selector", new JSONObject()
                .put("criteria", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("matches", new JSONArray()
                                        .put(new JSONObject()
                                                .put("field", "hdr.ethernet.ether_type")
                                                .put("match", "exact")
                                                .put("value", "27c0"))
                                        .put(new JSONObject()
                                                .put("field", "hdr.mf.src_guid")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(srcMFGuid,8)))
                                        .put(new JSONObject()
                                                .put("field", "hdr.mf.dest_guid")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(dstMFGuid,8)))))));
        return new JSONObject().put("flows", new JSONArray().put(flowObject));
    }

    public JSONObject generateNDNFlows(int switchID, int port, int srcIdentifier, int dstIdentifier) {
        int srcNDNName = 202271720 + vmx * 100000 + srcIdentifier - 64;
        int dstNDNName = 202271720 + vmx * 100000 + dstIdentifier - 64;
        int ndnContent = 2048 + vmx * 100 + srcIdentifier - 64;
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        log.warn("generateNDNFlows srcIdentifier:{}, dstIdentifier:{}, srcNDNName:{}, dstNDNName:{}, ndnContent:{}",
                srcIdentifier, dstIdentifier, srcNDNName, dstNDNName, ndnContent);
        String deviceID = String.format("device:domain1:group4:level%d:s%d",level, switchID + 300);
        JSONObject flowObject = new JSONObject();
        flowObject.put("priority", 10);
        flowObject.put("timeout", 0);
        flowObject.put("isPermanent", "true");
        flowObject.put("tableId",4);                // ndn的tableId=4
        flowObject.put("deviceId", deviceID);
        flowObject.put("treatment", new JSONObject()
                .put("instructions", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("subtype", "ACTION")
                                .put("actionId", "ingress.set_next_ndn_hop")
                                .put("actionParams", new JSONObject()
                                        .put("dst_port", String.format("%s", port))))));
        flowObject.put("clearDeferred", "true");
        flowObject.put("selector", new JSONObject()
                .put("criteria", new JSONArray()
                        .put(new JSONObject()
                                .put("type", "PROTOCOL_INDEPENDENT")
                                .put("matches", new JSONArray()
                                        .put(new JSONObject()
                                                .put("field", "hdr.ethernet.ether_type")
                                                .put("match", "exact")
                                                .put("value", "8624"))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ndn.ndn_prefix.code")
                                                .put("match", "exact")
                                                .put("value", "06"))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ndn.name_tlv.components[0].value")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(srcNDNName,8)))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ndn.name_tlv.components[1].value")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(dstNDNName,8)))
                                        .put(new JSONObject()
                                                .put("field", "hdr.ndn.content_tlv.value")
                                                .put("match", "exact")
                                                .put("value", decimal2Hex(ndnContent,4)))))));
        return new JSONObject().put("flows", new JSONArray().put(flowObject));
    }

    public void postFlow(String modalType, int switchID, int port, int srcIdentifier, int dstIdentifier) {
        String IP = "218.199.84.171";
        String APP_ID = "org.stratumproject.basic-tna";
        String urlString = String.format("http://%s:8181/onos/v1/flows?appId=%s",IP,APP_ID);
        String auth = "onos:rocks";
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

        JSONObject jsonData = null;

        switch (modalType) {
            case "ip":
                jsonData = generateIPFlows(switchID, port, srcIdentifier, dstIdentifier);
                break;
            case "id":
                jsonData = generateIDFlows(switchID, port, srcIdentifier, dstIdentifier);
                break;
            case "geo":
                // jsonData = generateGEOFlows(switchID, port, srcIdentifier, dstIdentifier);
                break;
            case "mf":
                jsonData = generateMFFlows(switchID, port, srcIdentifier, dstIdentifier);
                break;
            case "ndn":
                jsonData = generateNDNFlows(switchID, port, srcIdentifier, dstIdentifier);
                break;
            default:
                log.error("Invalid modal type: {}", modalType);
        }

        // 发送请求
        try {
            log.warn("------------data------------\n");
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
            connection.setDoOutput(true);

            // 发送JSON数据
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonData.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                log.warn("Success: " + connection.getResponseMessage());
            } else {
                log.warn("Status Code: " + responseCode);
                log.warn("Response Body: " + connection.getResponseMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

    public void executeAddFlow(String modalType, int srcHost, int dstHost) {
        int srcSwitch = srcHost-100;   // h180-eth0 <-> s80-eth2
        int dstSwitch = dstHost-100;   // h166-eth0 <-> s66-eth2
        int srcIdentifier = srcHost-100;
        int dstIdentifier = dstHost-100;
        ArrayList<Integer> involvedSwitches = new ArrayList<>();

        // 交换机的eth0\eth1\eth2对应转发端口0\1\2
        // srcSwitch至lca(srcSwitch,dstSwitch)路径中交换机需要下发流表（当前节点向父节点转发）
        // lca(srcSwitch,dstSwitch)至dstSwitch路径中交换机需要下发流表（当前节点的父节点向当前节点转发）

        postFlow(modalType, dstSwitch, 2, srcIdentifier, dstIdentifier);   // dstSwitch需要向网卡eth2的端口转发
        involvedSwitches.add(dstSwitch);

        int srcDepth = (int) Math.floor(Math.log(srcSwitch)/Math.log(2)) + 1;
        int dstDepth = (int) Math.floor(Math.log(dstSwitch)/Math.log(2)) + 1;

        log.warn("srcHost:{}, dstHost:{}, srcSwitch:{}, dstSwitch:{}, srcDepth:{}, dstDepth:{}",
                srcHost, dstHost, srcSwitch, dstSwitch, srcDepth, dstDepth);

        // srcSwitch深度更大
        if (srcDepth > dstDepth) {
            while (srcDepth != dstDepth) {
                postFlow(modalType, srcSwitch, 1, srcIdentifier, dstIdentifier);  // 只能通过eth1向父节点转发
                involvedSwitches.add(srcSwitch);
                srcSwitch = (int) Math.floor(srcSwitch / 2);
                srcDepth = srcDepth - 1;
            } 
        }

        // dstSwitch深度更大
        if (srcDepth < dstDepth) {
            while (srcDepth != dstDepth) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father*2 == dstSwitch) {
                    postFlow(modalType, father, 2, srcIdentifier, dstIdentifier);    // 通过eth2向左儿子转发
                } else {
                    postFlow(modalType, father, 3, srcIdentifier, dstIdentifier);   // 通过eth3向右儿子转发
                }
                involvedSwitches.add(father);
                dstSwitch = (int) Math.floor(dstSwitch / 2);
                dstDepth = dstDepth - 1;
            }
        }

        // srcSwitch和dstSwitch在同一层，srcSwitch向父节点转发，dstSwitch的父节点向dstSwitch转发
        while(true){
            postFlow(modalType, srcSwitch, 1, srcIdentifier, dstIdentifier);
            int father = (int) Math.floor(dstSwitch / 2);
            if (father*2 == dstSwitch) {
                postFlow(modalType, father, 2, srcIdentifier, dstIdentifier);
            } else {
                postFlow(modalType, father, 3, srcIdentifier, dstIdentifier);
            }
            involvedSwitches.add(srcSwitch);
            involvedSwitches.add(father);
            srcSwitch = (int) Math.floor(srcSwitch / 2);
            dstSwitch = (int) Math.floor(dstSwitch / 2);
            if (srcSwitch == dstSwitch) {
                break;
            }
        }
        log.warn("involvedSwitches:{}", involvedSwitches);
    }
    
    private int transferIP2Host(int param) {
        log.warn("transferIP2Host param:{}", param);
        int x = (param & 0xffff) >> 8;
        int i = param & 0xff + 64 - 12;
        return x * 100 + i;
    }

    private int transferID2Host(int param) {
        log.warn("transferID2Host param:{}",param);
        int x = (param - 202271720) / 100000;
        int i = param - 202271720 - x * 100000 + 64;
        return x * 100 + i;
    }

    private int transferMF2Host(int param) {
        log.warn("transferMF2Host param:{}", param);
        int x = (param - 1) / 100;
        int i = param - 1 - x * 100 + 64;
        return x * 100 + i;
    }

    private int transferNDN2Host(int param) {
        log.warn("transferNDN2Host param:{}", param);
        int x = (param - 202271720) / 100000;
        int i = param - 202271720 - x * 100000 + 64;
        return x * 100 + i;
    }

    public void handleModalPacket(int pktType, byte[] payload) {
        String modalType = "";
        int srcHost = 0, dstHost = 0;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        switch(pktType){
            case 0x0800:    // IP
                modalType = "ip";
                srcHost = transferIP2Host(buffer.getInt(12) & 0xffffffff);
                dstHost = transferIP2Host(buffer.getInt(16) & 0xffffffff);
                break;
            case 0x0812:    // ID
                modalType = "id";
                srcHost = transferID2Host(buffer.getInt(0) & 0xffffffff);
                dstHost = transferID2Host(buffer.getInt(4) & 0xffffffff);
                break;
            case 0x8947:    // GEO
                modalType = "geo";

                break;
            case 0x27c0:    // MF
                modalType = "mf";
                srcHost = transferMF2Host(buffer.getInt(4) & 0xffffffff);
                dstHost = transferMF2Host(buffer.getInt(8) & 0xffffffff);
                break;
            case 0x8624:    // NDN
                modalType = "ndn";
                srcHost = transferNDN2Host(buffer.getInt(8) & 0xffffffff);
                dstHost = transferNDN2Host(buffer.getInt(14) & 0xffffffff);
                break;
        }
        log.warn("modalType: {}, srcHost: {}, dstHost: {}", modalType, srcHost, dstHost);
        String path = "/home/onos/Desktop/ngsdn-tutorial/mininet/flows.out";
        String content = modalType + " " + srcHost + " " + dstHost;
        try (FileOutputStream fos = new FileOutputStream(path, true)) {
            fos.write(System.lineSeparator().getBytes());
            fos.write(content.getBytes());
            log.info("message written to file... {}", content);
        } catch (IOException e) {
            e.printStackTrace();
        }
        executeAddFlow(modalType, srcHost, dstHost);
    }

    public void parserPkt(int pktType,byte[] payload) throws DeserializationException {
        switch (pktType){
            case 0x0800:      // IP
                IP pkt;
                pkt = IP.deserializer().deserialize(payload,0,payload.length);
                log.warn("ip packet: {}",pkt);
                break;
            case 0x0812:      // ID
                int src_id = 0;
                int dst_id = 0;
                for (int i=0;i<4;i++) {
                    src_id |= ((payload[i]&0xff)<<(8*(3-i)));
                }
                for (int i=4;i<8;i++){
                    dst_id |= ((payload[i]&0xff)<<(8*(7-i)));
                }
                log.warn("id packet: {} {}",src_id, dst_id);
                break;
            case 0x8947:      // GEO
                int geoAreaPosLat = 0;
                int getAreaPosLon = 0;
                short disa = 0;
                short disb = 0;
                for(int i=40;i<44;i++){
                    geoAreaPosLat |= ((payload[i]&0xff)<<(8*(43-i)));
                }
                for (int i=44;i<48;i++){
                    getAreaPosLon |= ((payload[i]&0xff)<<(8*(47-i)));
                }
                for (int i=48;i<50;i++){
                    disa |= ((payload[i]&0xff)<<(8*(49-i)));
                }
                for(int i=50;i<52;i++){
                    disb |= ((payload[i]&0xff)<<(8*(51-i)));
                }
                log.warn("geo packet: {} {} {} {}", geoAreaPosLat, getAreaPosLon,disa, disb);
                break;
            case 0x27c0:      // MF
                int mf_type = 0;
                int src_guid = 0;
                int dst_guid = 0;
                ByteBuffer buffer = ByteBuffer.wrap(payload);
                mf_type = buffer.getInt(0) & 0xffffffff;
                src_guid = buffer.getInt(4) & 0xfffffff;
                dst_guid = buffer.getInt(8) & 0xfffffff;
                break;
            case 0x8624:      // NDN
                int name_component_src = 0;
                int name_component_dst = 0;
                short content = 0;
                for(int i=8;i<12;i++){
                    name_component_dst |= ((payload[i]&0xff)<<(8*(11-i)));
                }
                for(int i=14;i<18;i++){
                    name_component_src |= ((payload[i]&0xff)<<(8*(17-i)));
                }
                for(int i=34;i<36;i++){
                    content |= ((payload[i]&0xff)<<(8*(35-i)));
                }
                log.warn("ndn packet: {} {} {}", name_component_src, name_component_dst, content);
                break;
        }
    }


    @Override
    public Optional<PiAction> getOriginalDefaultAction(PiTableId tableId) {
        return Optional.empty();
    }

    @Override
    public Optional<Long> mapLogicalPort(PortNumber port) {
      if (!port.equals(CONTROLLER)) {
          return Optional.empty();
      }
      return capabilities.cpuPort();
    }

    /* Connect point generated using sb metadata does not have port name
       we use the device service as translation service */
    private ConnectPoint translateSwitchPort(ConnectPoint connectPoint) {
        final DeviceService deviceService = handler().get(DeviceService.class);
        if (deviceService == null) {
            log.warn("Unable to translate switch port due to DeviceService not available");
            return connectPoint;
        }
        Port devicePort = deviceService.getPort(connectPoint);
        if (devicePort != null) {
            return new ConnectPoint(connectPoint.deviceId(), devicePort.number());
        }
        return connectPoint;
    }
}
