import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { ChevronDown, ChevronUp, RotateCcw, ShieldAlert, X } from 'lucide-react';
import type { NetworkDeviceNode, NetworkEdge, ProtocolName, SecurityAlert } from '../../core/types';
import { formatBytes } from '../../utils/formatters';

interface NetworkUniverseProps {
  nodes: NetworkDeviceNode[];
  edges: NetworkEdge[];
  alerts: SecurityAlert[];
  selectedNodeIp: string | null;
  onSelectNode: (ip: string | null) => void;
  protocolFilter: ProtocolName | 'ALL';
  onProtocolFilterChange: (p: ProtocolName | 'ALL') => void;
  reducedMotion?: boolean;
  heightClass?: string;
}

// Pre-allocated scratch math helpers (zero GC inside render loop)
const _vA = new THREE.Vector3();
const _vB = new THREE.Vector3();
const _vPos = new THREE.Vector3();
const _quat = new THREE.Quaternion();
const _scale = new THREE.Vector3(1, 1, 1);
const _mat4 = new THREE.Matrix4();
const _col = new THREE.Color();

function createProceduralGridTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 512;
  canvas.height = 512;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#080510';
  ctx.fillRect(0, 0, 512, 512);

  ctx.strokeStyle = 'rgba(157, 0, 255, 0.16)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 512; i += 32) {
    ctx.beginPath();
    ctx.moveTo(i, 0);
    ctx.lineTo(i, 512);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(0, i);
    ctx.lineTo(512, i);
    ctx.stroke();
  }

  ctx.strokeStyle = 'rgba(40, 123, 255, 0.28)';
  ctx.lineWidth = 2;
  ctx.strokeRect(0, 0, 512, 512);

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(16, 16);
  return tex;
}

function createContactShadowTexture(): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 128;
  canvas.height = 128;
  const ctx = canvas.getContext('2d')!;
  const grad = ctx.createRadialGradient(64, 64, 6, 64, 64, 60);
  grad.addColorStop(0, 'rgba(0, 0, 0, 0.72)');
  grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 128, 128);
  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

function computeNodePositions(nodes: NetworkDeviceNode[]): Map<string, THREE.Vector3> {
  const positions = new Map<string, THREE.Vector3>();
  const count = nodes.length;
  if (count === 0) return positions;

  // Deterministic concentric rings: gateways/top talkers inner, others outer
  const sorted = [...nodes].sort((a, b) => b.packetCount - a.packetCount);
  sorted.forEach((node, i) => {
    if (i === 0) {
      positions.set(node.ip, new THREE.Vector3(0, 0, 0));
      return;
    }
    const ring = i <= 6 ? 1 : i <= 18 ? 2 : 3;
    const ringRadius = ring === 1 ? 6.2 : ring === 2 ? 12.2 : 18.0;
    const ringOffset = ring === 1 ? 1 : ring === 2 ? 7 : 19;
    const ringCapacity = ring === 1 ? Math.min(6, count - 1) : ring === 2 ? Math.min(12, count - 7) : Math.max(1, count - 19);
    const angle = ((i - ringOffset) / Math.max(1, ringCapacity)) * Math.PI * 2 + ring * 0.4;
    positions.set(
      node.ip,
      new THREE.Vector3(Math.cos(angle) * ringRadius, 0, Math.sin(angle) * ringRadius),
    );
  });
  return positions;
}

export const NetworkUniverse: React.FC<NetworkUniverseProps> = ({
  nodes,
  edges,
  alerts,
  selectedNodeIp,
  onSelectNode,
  protocolFilter,
  onProtocolFilterChange,
  reducedMotion = false,
  heightClass = 'h-[540px]',
}) => {
  const canvasMountRef = useRef<HTMLDivElement | null>(null);
  const [dockCollapsed, setDockCollapsed] = useState(false);
  const [autoOrbit, setAutoOrbit] = useState(false);
  const [webglUnavailable, setWebglUnavailable] = useState(false);

  const propsRef = useRef({
    nodes,
    edges,
    selectedNodeIp,
    onSelectNode,
    reducedMotion,
    autoOrbit,
  });
  propsRef.current = {
    nodes,
    edges,
    selectedNodeIp,
    onSelectNode,
    reducedMotion,
    autoOrbit,
  };

  const sceneApiRef = useRef<{
    rebuildGraph: () => void;
    resetCamera: () => void;
    requestRender: () => void;
  } | null>(null);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.ip === selectedNodeIp) ?? null,
    [nodes, selectedNodeIp],
  );

  const nodeAlerts = useMemo(
    () =>
      selectedNodeIp
        ? alerts.filter(
            (a) => a.sourceIp === selectedNodeIp || a.destinationIp === selectedNodeIp,
          )
        : [],
    [alerts, selectedNodeIp],
  );

  // Mount Three.js WebGLRenderer once
  useEffect(() => {
    const container = canvasMountRef.current;
    if (!container) return;

    const isSoftwareGl = (() => {
      try {
        const probe = document.createElement('canvas');
        const gl = probe.getContext('webgl2') || probe.getContext('webgl');
        if (!gl) return true;
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
        const gpu = String(gl.getParameter(param));
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
      } catch {
        return true;
      }
    })();

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: !isSoftwareGl,
        powerPreference: 'high-performance',
      });
    } catch {
      setWebglUnavailable(true);
      return;
    }

    const width = container.clientWidth || 960;
    const height = container.clientHeight || 540;

    renderer.setSize(width, height);
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x080510);
    scene.fog = new THREE.FogExp2(0x080510, 0.016);

    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    scene.environment = pmremGenerator.fromScene(new RoomEnvironment(), 0.04).texture;
    pmremGenerator.dispose();

    const camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 220);
    camera.position.set(0, 16, 22);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = !isSoftwareGl;
    controls.dampingFactor = 0.06;
    controls.minDistance = 6;
    controls.maxDistance = 48;
    controls.maxPolarAngle = Math.PI / 2.15;
    controls.target.set(0, 0.8, 0);

    // 3-point warm/cool studio lighting rig
    const hemi = new THREE.HemisphereLight(0x7cc8ff, 0x070910, 0.75);
    scene.add(hemi);

    const keyLight = new THREE.DirectionalLight(0xfff1dc, 1.8);
    keyLight.position.set(14, 22, 12);
    keyLight.castShadow = !isSoftwareGl;
    keyLight.shadow.mapSize.set(1024, 1024);
    keyLight.shadow.camera.left = -22;
    keyLight.shadow.camera.right = 22;
    keyLight.shadow.camera.top = 22;
    keyLight.shadow.camera.bottom = -22;
    keyLight.shadow.bias = -0.0005;
    keyLight.shadow.normalBias = 0.02;
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x00e5ff, 0.9);
    rimLight.position.set(-16, 10, -14);
    scene.add(rimLight);

    // Ground telemetry grid plane
    const gridTex = createProceduralGridTexture();
    gridTex.anisotropy = renderer.capabilities.getMaxAnisotropy();
    const floorGeo = new THREE.CircleGeometry(42, 64);
    floorGeo.rotateX(-Math.PI / 2);
    const floorMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      map: gridTex,
      roughness: 0.88,
      metalness: 0.12,
      polygonOffset: true,
      polygonOffsetFactor: 1,
      polygonOffsetUnits: 1,
    });
    const floor = new THREE.Mesh(floorGeo, floorMat);
    floor.receiveShadow = !isSoftwareGl;
    floor.position.y = -0.01;
    scene.add(floor);

    // Shared composite node geometries & materials (disposed on unmount)
    const shadowTex = createContactShadowTexture();
    const shadowGeo = new THREE.CircleGeometry(1.35, 24);
    shadowGeo.rotateX(-Math.PI / 2);
    const shadowMat = new THREE.MeshBasicMaterial({
      map: shadowTex,
      transparent: true,
      opacity: 0.48,
      depthWrite: false,
    });

    const plinthGeo = new THREE.CylinderGeometry(0.85, 1.02, 0.24, 8);
    const towerGeo = new THREE.CylinderGeometry(0.44, 0.56, 1.25, 8);
    const serverBodyGeo = new THREE.BoxGeometry(0.82, 1.45, 0.82);
    const unknownBodyGeo = new THREE.OctahedronGeometry(0.62, 0);
    const collarGeo = new THREE.TorusGeometry(0.66, 0.055, 10, 28);
    collarGeo.rotateX(Math.PI / 2);
    const mastGeo = new THREE.CylinderGeometry(0.035, 0.05, 0.72, 8);
    const beaconGeo = new THREE.OctahedronGeometry(0.16, 0);
    const proxyGeo = new THREE.CylinderGeometry(1.15, 1.15, 2.4, 12);
    const proxyMat = new THREE.MeshBasicMaterial({ visible: false });

    const plinthMat = new THREE.MeshStandardMaterial({
      color: 0x11192e,
      roughness: 0.78,
      metalness: 0.22,
    });
    const chassisMat = new THREE.MeshStandardMaterial({
      color: 0x1d2942,
      roughness: 0.28,
      metalness: 0.85,
    });

    const nodesGroup = new THREE.Group();
    const edgesGroup = new THREE.Group();
    scene.add(nodesGroup);
    scene.add(edgesGroup);

    // InstancedMesh for animated traffic pulse particles along edges
    const MAX_PARTICLES = 160;
    const particleGeo = new THREE.SphereGeometry(0.11, 10, 10);
    const particleMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const particleMesh = new THREE.InstancedMesh(particleGeo, particleMat, MAX_PARTICLES);
    particleMesh.frustumCulled = false;
    particleMesh.count = 0;
    scene.add(particleMesh);

    const interactables: THREE.Object3D[] = [];
    let activeEdgesData: Array<{
      start: THREE.Vector3;
      end: THREE.Vector3;
      hasAlert: boolean;
      speed: number;
      phase: number;
    }> = [];

    const edgeLineMatNormal = new THREE.LineBasicMaterial({
      color: 0x287bff,
      transparent: true,
      opacity: 0.48,
    });
    const edgeLineMatAlert = new THREE.LineBasicMaterial({
      color: 0xff3b5c,
      transparent: true,
      opacity: 0.82,
    });

    const nodeEmissiveMaterials: THREE.MeshStandardMaterial[] = [];

    function rebuildGraph() {
      // Clear previous nodes & edges
      while (nodesGroup.children.length > 0) {
        nodesGroup.remove(nodesGroup.children[0]);
      }
      while (edgesGroup.children.length > 0) {
        const obj = edgesGroup.children[0] as THREE.LineSegments;
        obj.geometry.dispose();
        edgesGroup.remove(obj);
      }
      nodeEmissiveMaterials.forEach((m) => m.dispose());
      nodeEmissiveMaterials.length = 0;
      interactables.length = 0;

      const { nodes: curNodes, edges: curEdges, selectedNodeIp: selIp } = propsRef.current;
      const posMap = computeNodePositions(curNodes);

      for (const node of curNodes) {
        const pos = posMap.get(node.ip);
        if (!pos) continue;

        const grp = new THREE.Group();
        grp.position.copy(pos);

        const intensityScale = Math.min(1.65, 0.85 + Math.log10(Math.max(1, node.packetCount)) * 0.28);
        grp.scale.setScalar(intensityScale);

        const isAlert = node.alertCount > 0;
        const isSelected = node.ip === selIp;
        const accentHex = isAlert
          ? 0xff3b5c
          : node.category === 'gateway'
          ? 0x00e5ff
          : node.category === 'server'
          ? 0x39ff88
          : node.category === 'unknown'
          ? 0x9b5cff
          : 0x287bff;

        const accentMat = new THREE.MeshStandardMaterial({
          color: accentHex,
          emissive: accentHex,
          emissiveIntensity: isSelected ? 1.5 : isAlert ? 1.15 : 0.65,
          roughness: 0.25,
          metalness: 0.6,
        });
        nodeEmissiveMaterials.push(accentMat);

        // Contact shadow disc
        const shadow = new THREE.Mesh(shadowGeo, shadowMat);
        shadow.position.y = 0.02;
        grp.add(shadow);

        // Part 1: Plinth base (bottom-center flush at y=0)
        const plinth = new THREE.Mesh(plinthGeo, plinthMat);
        plinth.position.y = 0.12;
        plinth.castShadow = !isSoftwareGl;
        plinth.receiveShadow = !isSoftwareGl;
        grp.add(plinth);

        // Part 2: Category-specific composite core
        const bodyGeo =
          node.category === 'server'
            ? serverBodyGeo
            : node.category === 'unknown'
            ? unknownBodyGeo
            : towerGeo;
        const body = new THREE.Mesh(bodyGeo, chassisMat);
        body.position.y = node.category === 'unknown' ? 0.92 : 0.86;
        body.castShadow = !isSoftwareGl;
        grp.add(body);

        // Part 3: Emissive status collar ring
        const collar = new THREE.Mesh(collarGeo, accentMat);
        collar.position.y = isSelected ? 0.55 : 0.36;
        grp.add(collar);

        // Part 4: Telemetry mast + Part 5: Beacon crystal
        const mast = new THREE.Mesh(mastGeo, chassisMat);
        mast.position.y = 1.75;
        grp.add(mast);

        const beacon = new THREE.Mesh(beaconGeo, accentMat);
        beacon.position.y = 2.18;
        grp.add(beacon);

        // Proxy collider for crisp raycasting
        const proxy = new THREE.Mesh(proxyGeo, proxyMat);
        proxy.position.y = 1.1;
        proxy.layers.set(1);
        proxy.userData.ip = node.ip;
        grp.add(proxy);
        interactables.push(proxy);

        nodesGroup.add(grp);
      }

      // Build batched edges
      const normalPts: number[] = [];
      const alertPts: number[] = [];
      activeEdgesData = [];

      curEdges.forEach((edge, idx) => {
        const sPos = posMap.get(edge.source);
        const tPos = posMap.get(edge.target);
        if (!sPos || !tPos) return;
        const y = 0.72;
        if (edge.hasAlert) {
          alertPts.push(sPos.x, y, sPos.z, tPos.x, y, tPos.z);
        } else {
          normalPts.push(sPos.x, y, sPos.z, tPos.x, y, tPos.z);
        }
        activeEdgesData.push({
          start: new THREE.Vector3(sPos.x, y, sPos.z),
          end: new THREE.Vector3(tPos.x, y, tPos.z),
          hasAlert: edge.hasAlert,
          speed: 0.25 + Math.min(0.65, edge.packets * 0.02),
          phase: (idx * 0.37) % 1,
        });
      });

      if (normalPts.length > 0) {
        const g = new THREE.BufferGeometry();
        g.setAttribute('position', new THREE.Float32BufferAttribute(normalPts, 3));
        edgesGroup.add(new THREE.LineSegments(g, edgeLineMatNormal));
      }
      if (alertPts.length > 0) {
        const g = new THREE.BufferGeometry();
        g.setAttribute('position', new THREE.Float32BufferAttribute(alertPts, 3));
        edgesGroup.add(new THREE.LineSegments(g, edgeLineMatAlert));
      }

      const pCount = Math.min(MAX_PARTICLES, activeEdgesData.length * 2);
      particleMesh.count = pCount;
      for (let i = 0; i < pCount; i++) {
        const edge = activeEdgesData[i % activeEdgesData.length];
        _col.setHex(edge.hasAlert ? 0xff3b5c : 0x00e5ff);
        particleMesh.setColorAt(i, _col);
      }
      if (particleMesh.instanceColor) particleMesh.instanceColor.needsUpdate = true;
    }

    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }
    rebuildGraph();

    // Raycasting on pointer click (layer 1 only)
    const raycaster = new THREE.Raycaster();
    raycaster.layers.set(1);
    const pointer = new THREE.Vector2();
    let pointerDownPos = { x: 0, y: 0 };

    const onPointerDown = (e: PointerEvent) => {
      pointerDownPos = { x: e.clientX, y: e.clientY };
    };
    const onPointerUp = (e: PointerEvent) => {
      const dist = Math.hypot(e.clientX - pointerDownPos.x, e.clientY - pointerDownPos.y);
      if (dist > 6) return;
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(interactables, false);
      if (hits.length > 0) {
        const ip = hits[0].object.userData.ip as string | undefined;
        if (ip) propsRef.current.onSelectNode(ip);
      }
    };

    renderer.domElement.addEventListener('pointerdown', onPointerDown);
    renderer.domElement.addEventListener('pointerup', onPointerUp);

    // Resize observer
    const onResize = () => {
      if (!container) return;
      const w = container.clientWidth || 960;
      const h = container.clientHeight || 540;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
      requestRender();
    };
    window.addEventListener('resize', onResize);

    let frameId = 0;
    let disposed = false;
    const clock = new THREE.Clock();

    function afterDraw(cb: () => void) {
      if (disposed) return;
      const gl = renderer.getContext() as WebGL2RenderingContext;
      const sync = gl.fenceSync ? gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0) : null;
      gl.flush();
      const poll = () => {
        if (disposed) return;
        const state = sync && gl.getSyncParameter ? gl.getSyncParameter(sync, gl.SYNC_STATUS) : gl.SIGNALED;
        if (state === gl.UNSIGNALED) {
          frameId = window.setTimeout(poll, 5);
        } else {
          if (sync && gl.deleteSync) gl.deleteSync(sync);
          frameId = window.setTimeout(cb, 80);
        }
      };
      frameId = window.setTimeout(poll, 5);
    }

    function updateParticles(elapsed: number) {
      if (activeEdgesData.length === 0 || particleMesh.count === 0) return;
      for (let i = 0; i < particleMesh.count; i++) {
        const edge = activeEdgesData[i % activeEdgesData.length];
        const offset = i >= activeEdgesData.length ? 0.5 : 0;
        const t = propsRef.current.reducedMotion
          ? 0.5
          : (edge.phase + offset + elapsed * edge.speed) % 1;
        _vA.copy(edge.start);
        _vB.copy(edge.end);
        _vPos.lerpVectors(_vA, _vB, t);
        _mat4.compose(_vPos, _quat, _scale);
        particleMesh.setMatrixAt(i, _mat4);
      }
      particleMesh.instanceMatrix.needsUpdate = true;
    }

    let renderBusy = false;
    let renderDirty = false;
    function requestRender() {
      if (disposed) return;
      if (renderBusy) {
        renderDirty = true;
        return;
      }
      renderBusy = true;
      frameId = requestAnimationFrame(() => {
        if (disposed) return;
        renderDirty = false;
        controls.update();
        updateParticles(clock.getElapsedTime());
        renderer.render(scene, camera);
        const done = () => {
          renderBusy = false;
          if (renderDirty && !disposed) requestRender();
        };
        if (isSoftwareGl) afterDraw(done);
        else done();
      });
    }

    function tick() {
      if (disposed) return;
      controls.autoRotate = !isSoftwareGl && propsRef.current.autoOrbit && !propsRef.current.reducedMotion;
      controls.autoRotateSpeed = 0.8;
      controls.update();
      updateParticles(clock.getElapsedTime());
      renderer.render(scene, camera);

      if (propsRef.current.reducedMotion) {
        // Static on-demand only when reduced motion is active
        return;
      }
      if (isSoftwareGl) {
        afterDraw(tick);
      } else {
        frameId = requestAnimationFrame(tick);
      }
    }

    controls.addEventListener('change', () => {
      if (propsRef.current.reducedMotion || isSoftwareGl) {
        requestRender();
      }
    });

    sceneApiRef.current = {
      rebuildGraph: () => {
        rebuildGraph();
        requestRender();
      },
      resetCamera: () => {
        camera.position.set(0, 16, 22);
        controls.target.set(0, 0.8, 0);
        controls.update();
        requestRender();
      },
      requestRender,
    };

    if (propsRef.current.reducedMotion) {
      requestRender();
    } else {
      tick();
    }

    return () => {
      disposed = true;
      cancelAnimationFrame(frameId);
      clearTimeout(frameId);
      window.removeEventListener('resize', onResize);
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      renderer.domElement.removeEventListener('pointerup', onPointerUp);
      controls.dispose();
      gridTex.dispose();
      shadowTex.dispose();
      floorGeo.dispose();
      floorMat.dispose();
      shadowGeo.dispose();
      shadowMat.dispose();
      plinthGeo.dispose();
      towerGeo.dispose();
      serverBodyGeo.dispose();
      unknownBodyGeo.dispose();
      collarGeo.dispose();
      mastGeo.dispose();
      beaconGeo.dispose();
      proxyGeo.dispose();
      proxyMat.dispose();
      plinthMat.dispose();
      chassisMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      edgeLineMatNormal.dispose();
      edgeLineMatAlert.dispose();
      nodeEmissiveMaterials.forEach((m) => m.dispose());
      renderer.dispose();
    };
  }, []);

  // Trigger graph rebuild cleanly without remounting WebGLRenderer
  useEffect(() => {
    sceneApiRef.current?.rebuildGraph();
  }, [nodes, edges, selectedNodeIp]);

  return (
    <div
      className={`relative w-full ${heightClass} bg-[#080510] border border-[#C9A4FF]/20 rounded-xl overflow-hidden`}
      data-testid="network-universe-viewport"
    >
      {/* Isolated WebGL mount container */}
      <div ref={canvasMountRef} className="w-full h-full" />

      {webglUnavailable && (
        <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#080510] text-slate-300 p-6 text-center">
          <p className="font-display font-semibold text-base">3D WebGL Context Unavailable</p>
          <p className="text-xs text-slate-400 mt-1 max-w-md">
            Your browser environment blocked WebGL initialization. Observed topology metrics remain available below.
          </p>
        </div>
      )}

      {/* Minimal Top-Left Spec Badge */}
      <div className="absolute top-3 left-3 px-3 py-1.5 rounded-lg bg-[#10091B]/95 border border-[#C9A4FF]/20 text-xs text-slate-300 flex items-center gap-2 pointer-events-none">
        <span className="font-display font-semibold text-slate-100">Observed Topology</span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className="font-mono tabular-nums text-[#00E5FF]">{nodes.length} nodes</span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className="font-mono tabular-nums text-slate-400">{edges.length} links</span>
      </div>

      {/* Selected Node Inspection Drawer (only shown when user selects a node) */}
      {selectedNode && (
        <div className="absolute top-3 right-3 w-72 bg-[#10091B]/95 border border-[#C9A4FF]/25 rounded-xl p-4 text-xs space-y-3 shadow-2xl">
          <div className="flex items-start justify-between gap-2 pb-2 border-b border-slate-800">
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-slate-400">
                {selectedNode.category === 'unknown' ? 'Unknown Endpoint' : selectedNode.category}
              </p>
              <p className="font-mono font-semibold text-sm text-[#00E5FF] truncate">
                {selectedNode.ip}
              </p>
            </div>
            <button
              type="button"
              onClick={() => onSelectNode(null)}
              aria-label="Close node details"
              className="p-1 text-slate-400 hover:text-slate-100 rounded"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2 font-mono tabular-nums">
            <div>
              <span className="text-slate-500 block text-[11px]">Packets</span>
              <span className="text-slate-100 font-semibold">{selectedNode.packetCount}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Volume</span>
              <span className="text-slate-100 font-semibold">{formatBytes(selectedNode.byteVolume)}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Inbound / Out</span>
              <span className="text-slate-200">
                {selectedNode.inboundCount} / {selectedNode.outboundCount}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[11px]">Alerts</span>
              <span className={selectedNode.alertCount > 0 ? 'text-[#FF3B5C] font-semibold' : 'text-[#39FF88]'}>
                {selectedNode.alertCount}
              </span>
            </div>
          </div>

          <div>
            <span className="text-slate-500 block mb-1">Observed Protocols</span>
            <p className="font-mono text-slate-200">
              {selectedNode.protocols.join(' · ') || 'None'}
            </p>
          </div>

          <div>
            <span className="text-slate-500 block mb-1">Peers ({selectedNode.connectedPeers.length})</span>
            <p className="font-mono text-slate-300 break-all max-h-14 overflow-y-auto">
              {selectedNode.connectedPeers.slice(0, 6).join(', ')}
            </p>
          </div>

          {nodeAlerts.length > 0 && (
            <div className="pt-2 border-t border-slate-800 space-y-1">
              <div className="flex items-center gap-1.5 text-[#FF3B5C] font-semibold">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Associated Alerts</span>
              </div>
              {nodeAlerts.slice(0, 2).map((a) => (
                <p key={a.id} className="text-slate-300 leading-snug">
                  {a.severity}: {a.ruleName}
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Unified Collapsible Bottom Control Dock (solid rgba, NO backdrop-filter over WebGL) */}
      <div className="absolute bottom-3 left-1/2 -translate-x-1/2 max-w-[96%] flex flex-col items-center">
        <button
          type="button"
          onClick={() => setDockCollapsed((v) => !v)}
          className="px-3 py-0.5 rounded-t-lg bg-[#10091B]/95 border border-b-0 border-[#C9A4FF]/20 text-[11px] font-medium text-slate-300 hover:text-white flex items-center gap-1.5 whitespace-nowrap"
        >
          {dockCollapsed ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          {dockCollapsed ? 'Show Controls' : 'Hide Controls'}
        </button>

        {!dockCollapsed && (
          <div className="bg-[#10091B]/95 border border-[#C9A4FF]/20 rounded-xl px-3 py-1.5 flex flex-wrap sm:flex-nowrap items-center justify-center gap-2.5 text-xs shadow-xl">
            <div className="flex items-center gap-1.5">
              <label htmlFor="topo-proto-select" className="text-slate-400 whitespace-nowrap">
                Protocol
              </label>
              <select
                id="topo-proto-select"
                value={protocolFilter}
                onChange={(e) => onProtocolFilterChange(e.target.value as ProtocolName | 'ALL')}
                className="bg-[#080510] border border-[#C9A4FF]/25 rounded-md px-2 py-1 text-xs text-slate-100 focus:outline-none focus:border-[#00E5FF]"
              >
                <option value="ALL">All Protocols</option>
                <option value="HTTPS/TLS">HTTPS/TLS</option>
                <option value="DNS">DNS</option>
                <option value="HTTP">HTTP</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ARP">ARP</option>
              </select>
            </div>

            {nodes.length > 0 && (
              <div className="flex items-center gap-1.5">
                <label htmlFor="topo-node-select" className="text-slate-400 whitespace-nowrap">
                  Endpoint
                </label>
                <select
                  id="topo-node-select"
                  value={selectedNodeIp ?? ''}
                  onChange={(e) => onSelectNode(e.target.value || null)}
                  className="bg-[#080510] border border-[#C9A4FF]/25 rounded-md px-2 py-1 text-xs font-mono text-slate-100 focus:outline-none focus:border-[#00E5FF]"
                >
                  <option value="">Select IP...</option>
                  {nodes.slice(0, 20).map((n) => (
                    <option key={n.ip} value={n.ip}>
                      {n.ip} ({n.packetCount})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              type="button"
              onClick={() => setAutoOrbit((v) => !v)}
              className={`px-2.5 py-1 rounded-md border text-xs font-medium whitespace-nowrap transition-colors ${
                autoOrbit
                  ? 'border-[#00E5FF]/60 bg-[#00E5FF]/15 text-[#00E5FF]'
                  : 'border-slate-700 text-slate-300 hover:border-slate-500'
              }`}
            >
              {autoOrbit ? 'Orbiting' : 'Auto-Orbit'}
            </button>

            <button
              type="button"
              onClick={() => sceneApiRef.current?.resetCamera()}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500 whitespace-nowrap transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset View
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
