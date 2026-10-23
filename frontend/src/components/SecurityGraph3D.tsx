import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

interface SecurityGraph3DProps {
  className?: string;
  subtle?: boolean;
}

/**
 * Creates a glowing circular dot texture on an offscreen canvas
 * so vertices render as radiant, glowing nodes rather than flat square points.
 */
function createGlowDotTexture(colorInner: string, colorOuter: string): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext('2d')!;
  const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, '#ffffff');
  gradient.addColorStop(0.25, colorInner);
  gradient.addColorStop(0.6, colorOuter);
  gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(canvas);
}

export const SecurityGraph3D: React.FC<SecurityGraph3DProps> = ({
  className = '',
  subtle = false,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let width = container.clientWidth || window.innerWidth;
    let height = container.clientHeight || window.innerHeight;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    // Position camera to frame the scene gracefully around center text
    camera.position.z = subtle ? 8.5 : 6.4;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Group for combined rotation
    const shieldGroup = new THREE.Group();
    scene.add(shieldGroup);

    // Multipliers for subtle vs full-bleed
    const opacityMultiplier = subtle ? 0.35 : 1.0;

    // 1. Outer Polyhedron: Attack-path graph lattice (Vibrant Emerald)
    const outerGeo = new THREE.IcosahedronGeometry(2.6, 1);
    const outerWireframe = new THREE.WireframeGeometry(outerGeo);
    const outerMat = new THREE.LineBasicMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.72 * opacityMultiplier,
      linewidth: 1.5,
    });
    const outerMesh = new THREE.LineSegments(outerWireframe, outerMat);
    shieldGroup.add(outerMesh);

    // 2. Vertex Nodes on Outer Lattice (Radiant Glowing Points)
    const nodePositions: number[] = [];
    const posAttribute = outerGeo.getAttribute('position');
    for (let i = 0; i < posAttribute.count; i++) {
      nodePositions.push(posAttribute.getX(i), posAttribute.getY(i), posAttribute.getZ(i));
    }
    const nodesGeo = new THREE.BufferGeometry();
    nodesGeo.setAttribute('position', new THREE.Float32BufferAttribute(nodePositions, 3));
    
    const glowTexture = createGlowDotTexture('#34d399', 'rgba(16, 185, 129, 0.5)');
    const nodesMat = new THREE.PointsMaterial({
      color: 0xa7f3d0,
      size: subtle ? 0.14 : 0.32,
      map: glowTexture,
      transparent: true,
      opacity: 0.95 * opacityMultiplier,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const nodesMesh = new THREE.Points(nodesGeo, nodesMat);
    shieldGroup.add(nodesMesh);

    // 3. Inner Core: Defense Vault (Vibrant Cyber Violet / Indigo)
    const innerGeo = new THREE.OctahedronGeometry(1.5, 0);
    const innerWireframe = new THREE.WireframeGeometry(innerGeo);
    const innerMat = new THREE.LineBasicMaterial({
      color: 0xa855f7,
      transparent: true,
      opacity: 0.85 * opacityMultiplier,
      linewidth: 2,
    });
    const innerMesh = new THREE.LineSegments(innerWireframe, innerMat);
    shieldGroup.add(innerMesh);

    // Inner Core Vertex Nodes (Violet glowing points)
    const innerPositions: number[] = [];
    const innerPosAttr = innerGeo.getAttribute('position');
    for (let i = 0; i < innerPosAttr.count; i++) {
      innerPositions.push(innerPosAttr.getX(i), innerPosAttr.getY(i), innerPosAttr.getZ(i));
    }
    const innerNodesGeo = new THREE.BufferGeometry();
    innerNodesGeo.setAttribute('position', new THREE.Float32BufferAttribute(innerPositions, 3));
    const violetGlowTexture = createGlowDotTexture('#c084fc', 'rgba(168, 85, 247, 0.5)');
    const innerNodesMat = new THREE.PointsMaterial({
      color: 0xe9d5ff,
      size: subtle ? 0.12 : 0.28,
      map: violetGlowTexture,
      transparent: true,
      opacity: 0.9 * opacityMultiplier,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const innerNodesMesh = new THREE.Points(innerNodesGeo, innerNodesMat);
    shieldGroup.add(innerNodesMesh);

    // 4. Center Glowing Security Core
    const coreGeo = new THREE.SphereGeometry(0.65, 16, 16);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x818cf8,
      wireframe: true,
      transparent: true,
      opacity: 0.6 * opacityMultiplier,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    shieldGroup.add(coreMesh);

    // 5. Floating Ambient Data Particles
    const particleCount = subtle ? 70 : 180;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      particlePositions[i] = (Math.random() - 0.5) * 11;
      particlePositions[i + 1] = (Math.random() - 0.5) * 11;
      particlePositions[i + 2] = (Math.random() - 0.5) * 8;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0xc084fc,
      size: 0.05,
      transparent: true,
      opacity: 0.65 * opacityMultiplier,
      blending: THREE.AdditiveBlending,
    });
    const particleField = new THREE.Points(particleGeo, particleMat);
    scene.add(particleField);

    // Mouse movement interaction across window
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const x = e.clientX / window.innerWidth - 0.5;
      const y = e.clientY / window.innerHeight - 0.5;
      targetX = x * 1.0;
      targetY = y * 1.0;
    };

    window.addEventListener('mousemove', handleMouseMove);

    // Resize handling
    const handleResize = () => {
      if (!container) return;
      width = container.clientWidth || window.innerWidth;
      height = container.clientHeight || window.innerHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };

    window.addEventListener('resize', handleResize);

    // Animation Loop
    let animationFrameId: number;
    const clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Smooth mouse follow
      mouseX += (targetX - mouseX) * 0.045;
      mouseY += (targetY - mouseY) * 0.045;

      // Rotations
      outerMesh.rotation.y = elapsedTime * 0.12 + mouseX;
      outerMesh.rotation.x = Math.sin(elapsedTime * 0.14) * 0.2 + mouseY;

      nodesMesh.rotation.y = outerMesh.rotation.y;
      nodesMesh.rotation.x = outerMesh.rotation.x;

      innerMesh.rotation.y = -elapsedTime * 0.18 + mouseX * 0.45;
      innerMesh.rotation.z = Math.cos(elapsedTime * 0.1) * 0.25;

      innerNodesMesh.rotation.y = innerMesh.rotation.y;
      innerNodesMesh.rotation.z = innerMesh.rotation.z;

      coreMesh.rotation.x = elapsedTime * 0.2;
      coreMesh.rotation.y = elapsedTime * 0.25;

      // Subtle breathing scale
      const scale = 1 + Math.sin(elapsedTime * 1.5) * 0.035;
      shieldGroup.scale.set(scale, scale, scale);

      particleField.rotation.y = elapsedTime * 0.03;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);

      // Clean up Three.js WebGL resources
      outerGeo.dispose();
      outerWireframe.dispose();
      outerMat.dispose();
      nodesGeo.dispose();
      nodesMat.dispose();
      glowTexture.dispose();
      innerGeo.dispose();
      innerWireframe.dispose();
      innerMat.dispose();
      innerNodesGeo.dispose();
      innerNodesMat.dispose();
      violetGlowTexture.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      renderer.dispose();

      if (container && renderer.domElement) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [subtle]);

  return (
    <div
      ref={mountRef}
      className={`w-full h-full pointer-events-none select-none ${className}`}
      aria-hidden="true"
    />
  );
};
