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
                // 解析各种模态
                parserPkt(pktType,payload);

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
            } catch (DeserializationException e) {
                throw new RuntimeException(e);
            }
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
        }
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
                for (int i=0;i<4;i++) {
                    mf_type |= ((payload[i]&0xff)<<(8*i));
                }
                for (int i=4;i<8;i++){
                    src_guid |= ((payload[i]&0xff)<<(8*(i-4)));
                }
                for (int i=8;i<12;i++){
                    dst_guid |= ((payload[i]&0xff)<<(8*(i-8)));
                }
                log.warn("mf packet: {} {} {}", mf_type, src_guid, dst_guid);
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
        String scriptPath = "/home/onos/Desktop/scripts/addFlow.py";
        String command = "python3" + scriptPath;
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
