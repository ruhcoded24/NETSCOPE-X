import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

interface RotatingGlobeCanvasProps {
  reducedMotion?: boolean;
  size?: number;
}

export const RotatingGlobeCanvas: React.FC<RotatingGlobeCanvasProps> = ({
  reducedMotion = false,
  size = 112,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [fallback, setFallback] = useState(false);

  useEffect(() => {
    const container = mountRef.current;
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
        alpha: true,
        powerPreference: 'low-power',
      });
    } catch {
      setFallback(true);
      return;
    }

    renderer.setSize(size, size);
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 30);
    camera.position.set(0, 0.65, 3.3);
    camera.lookAt(0, 0, 0);

    const globeGroup = new THREE.Group();
    globeGroup.rotation.z = 0.22;
    scene.add(globeGroup);

    // Wireframe network sphere
    const sphereGeo = new THREE.SphereGeometry(0.92, 16, 12);
    const wireGeo = new THREE.WireframeGeometry(sphereGeo);
    const wireMat = new THREE.LineBasicMaterial({
      color: 0x00e5ff,
      transparent: true,
      opacity: 0.42,
    });
    const wireMesh = new THREE.LineSegments(wireGeo, wireMat);
    globeGroup.add(wireMesh);

    // Inner violet core shell
    const coreGeo = new THREE.SphereGeometry(0.84, 16, 12);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x190626,
      transparent: true,
      opacity: 0.72,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    globeGroup.add(coreMesh);

    // Tilted orbital ring
    const ringGeo = new THREE.TorusGeometry(1.16, 0.015, 8, 48);
    ringGeo.rotateX(Math.PI / 2.3);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xff00c8,
      transparent: true,
      opacity: 0.65,
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    globeGroup.add(ringMesh);

    // Endpoint nodes distributed on globe surface
    const posAttr = sphereGeo.getAttribute('position');
    const nodePositions: number[] = [];
    for (let i = 0; i < posAttr.count; i += 5) {
      nodePositions.push(posAttr.getX(i), posAttr.getY(i), posAttr.getZ(i));
    }
    const ptsGeo = new THREE.BufferGeometry();
    ptsGeo.setAttribute('position', new THREE.Float32BufferAttribute(nodePositions, 3));
    const ptsMat = new THREE.PointsMaterial({
      color: 0xff36e2,
      size: 0.085,
      transparent: true,
      opacity: 0.9,
    });
    const pts = new THREE.Points(ptsGeo, ptsMat);
    globeGroup.add(pts);

    let disposed = false;
    let timerId = 0;

    const renderOnce = () => {
      if (disposed) return;
      renderer.render(scene, camera);
    };

    const afterDraw = (cb: () => void) => {
      if (disposed) return;
      const gl = renderer.getContext() as WebGL2RenderingContext;
      const sync = gl.fenceSync ? gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0) : null;
      gl.flush();
      const poll = () => {
        if (disposed) return;
        const state = sync && gl.getSyncParameter ? gl.getSyncParameter(sync, gl.SYNC_STATUS) : gl.SIGNALED;
        if (state === gl.UNSIGNALED) {
          timerId = window.setTimeout(poll, 8);
        } else {
          if (sync && gl.deleteSync) gl.deleteSync(sync);
          timerId = window.setTimeout(cb, 90);
        }
      };
      timerId = window.setTimeout(poll, 8);
    };

    const tick = () => {
      if (disposed) return;
      globeGroup.rotation.y += isSoftwareGl ? 0.025 : 0.008;
      ringMesh.rotation.z += 0.004;
      renderer.render(scene, camera);
      if (reducedMotion) return;
      if (isSoftwareGl) {
        afterDraw(tick);
      } else {
        timerId = requestAnimationFrame(tick);
      }
    };

    if (reducedMotion) {
      renderOnce();
    } else {
      tick();
    }

    return () => {
      disposed = true;
      cancelAnimationFrame(timerId);
      clearTimeout(timerId);
      sphereGeo.dispose();
      wireGeo.dispose();
      wireMat.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      ringGeo.dispose();
      ringMat.dispose();
      ptsGeo.dispose();
      ptsMat.dispose();
      renderer.dispose();
    };
  }, [reducedMotion, size]);

  if (fallback) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 112 112"
        className="shrink-0"
        role="img"
        aria-label="Network globe wireframe"
      >
        <circle cx="56" cy="56" r="40" fill="#190626" stroke="#00E5FF" strokeOpacity="0.55" />
        <ellipse cx="56" cy="56" rx="20" ry="40" fill="none" stroke="#00E5FF" strokeOpacity="0.35" />
        <ellipse cx="56" cy="56" rx="40" ry="16" fill="none" stroke="#FF00C8" strokeOpacity="0.45" />
        <circle cx="38" cy="44" r="2.5" fill="#FF36E2" />
        <circle cx="74" cy="60" r="2.5" fill="#00E5FF" />
      </svg>
    );
  }

  return (
    <div
      ref={mountRef}
      style={{ width: size, height: size }}
      className="relative flex items-center justify-center"
      aria-label="Rotating 3D network telemetry globe"
    />
  );
};
