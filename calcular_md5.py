#!/usr/bin/env python3
"""
Script de Utilidad para Control de Versiones
MyChat - Sistema de Chat Seguro

Este script calcula y muestra los hashes MD5 de todos los archivos .py del proyecto,
facilitando la documentación de cambios en readme.txt y control_cambios.txt.

Uso:
    python calcular_md5.py

El script generará un reporte formateado con los MD5 de todos los archivos Python.
"""

import hashlib
import os
from pathlib import Path
from datetime import datetime


def calcular_md5(ruta_archivo):
    """
    Calcula el hash MD5 de un archivo.
    
    Args:
        ruta_archivo (str): Ruta al archivo
        
    Returns:
        str: Hash MD5 en mayúsculas
    """
    hash_md5 = hashlib.md5()
    try:
        with open(ruta_archivo, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest().upper()
    except Exception as e:
        return f"ERROR: {e}"


def obtener_archivos_python():
    """
    Busca todos los archivos .py en el proyecto (excluyendo este script).
    
    Returns:
        list: Lista de tuplas (ruta_relativa, ruta_absoluta)
    """
    proyecto_root = Path(__file__).parent
    archivos = []
    
    # Buscar en simetrica/
    simetrica_dir = proyecto_root / "simetrica"
    if simetrica_dir.exists():
        for archivo in simetrica_dir.glob("*.py"):
            ruta_rel = f"simetrica/{archivo.name}"
            archivos.append((ruta_rel, str(archivo)))
    
    # Buscar en asimetrica/
    asimetrica_dir = proyecto_root / "asimetrica"
    if asimetrica_dir.exists():
        for archivo in asimetrica_dir.glob("*.py"):
            ruta_rel = f"asimetrica/{archivo.name}"
            archivos.append((ruta_rel, str(archivo)))
    
    # Ordenar por nombre de ruta
    archivos.sort(key=lambda x: x[0])
    
    return archivos


def generar_reporte_md5():
    """
    Genera un reporte formateado con los MD5 de todos los archivos Python.
    """
    print("=" * 80)
    print(" " * 20 + "REPORTE DE HASHES MD5 - MyChat")
    print(" " * 25 + f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("=" * 80)
    print()
    
    archivos = obtener_archivos_python()
    
    if not archivos:
        print("No se encontraron archivos .py en el proyecto.")
        return
    
    print("ARCHIVOS Y HASHES MD5:")
    print("┌─────────────────────────────┬──────────────────────────────────┐")
    print("│ Archivo                     │ MD5                              │")
    print("├─────────────────────────────┼──────────────────────────────────┤")
    
    for ruta_rel, ruta_abs in archivos:
        md5 = calcular_md5(ruta_abs)
        # Formatear para que quepa en la tabla
        archivo_fmt = ruta_rel.ljust(27)
        md5_fmt = md5.ljust(32)
        print(f"│ {archivo_fmt} │ {md5_fmt} │")
    
    print("└─────────────────────────────┴──────────────────────────────────┘")
    print()
    
    # Formato adicional para copiar directamente a documentos
    print("=" * 80)
    print("FORMATO PARA DOCUMENTACIÓN:")
    print("=" * 80)
    print()
    
    for ruta_rel, ruta_abs in archivos:
        md5 = calcular_md5(ruta_abs)
        print(f"{ruta_rel}")
        print(f"   MD5: {md5}")
        print()
    
    print("=" * 80)
    print("FORMATO COMPACTO (una línea por archivo):")
    print("=" * 80)
    print()
    
    for ruta_rel, ruta_abs in archivos:
        md5 = calcular_md5(ruta_abs)
        print(f"{ruta_rel} | {md5}")
    
    print()
    print("=" * 80)
    print("Reporte generado exitosamente.")
    print("Copia estos hashes a readme.txt y control_cambios.txt para documentar")
    print("la nueva versión.")
    print("=" * 80)


def verificar_integridad(hashes_esperados):
    """
    Verifica que los archivos actuales coincidan con los hashes esperados.
    
    Args:
        hashes_esperados (dict): Diccionario {ruta_relativa: hash_md5}
        
    Returns:
        tuple: (archivos_ok, archivos_modificados, archivos_faltantes)
    """
    archivos = obtener_archivos_python()
    archivos_dict = {ruta_rel: ruta_abs for ruta_rel, ruta_abs in archivos}
    
    archivos_ok = []
    archivos_modificados = []
    archivos_faltantes = []
    
    for ruta_rel, hash_esperado in hashes_esperados.items():
        if ruta_rel not in archivos_dict:
            archivos_faltantes.append(ruta_rel)
        else:
            hash_actual = calcular_md5(archivos_dict[ruta_rel])
            if hash_actual == hash_esperado.upper():
                archivos_ok.append(ruta_rel)
            else:
                archivos_modificados.append((ruta_rel, hash_esperado, hash_actual))
    
    return archivos_ok, archivos_modificados, archivos_faltantes


def verificar_version_1_0_0():
    """
    Verifica que los archivos actuales coincidan con la versión 1.0.0.
    """
    hashes_v1_0_0 = {
        "simetrica/service.py": "4AAB3B47E85B88C5F461E39AB63834A1",
        "simetrica/client.py": "93F14E26C869857EA73961B2C1211E69",
        "asimetrica/service.py": "867CE08AB0C1023CBC04A10852410730",
        "asimetrica/client.py": "CAC8C6592EA48BDDCD9D9AB521FE0D3F"
    }
    
    print("=" * 80)
    print(" " * 20 + "VERIFICACIÓN DE INTEGRIDAD - Versión 1.0.0")
    print("=" * 80)
    print()
    
    ok, modificados, faltantes = verificar_integridad(hashes_v1_0_0)
    
    if faltantes:
        print("❌ ARCHIVOS FALTANTES:")
        for archivo in faltantes:
            print(f"   - {archivo}")
        print()
    
    if modificados:
        print("⚠️  ARCHIVOS MODIFICADOS:")
        for archivo, esperado, actual in modificados:
            print(f"   - {archivo}")
            print(f"     Esperado: {esperado}")
            print(f"     Actual:   {actual}")
        print()
    
    if ok:
        print("✓ ARCHIVOS CORRECTOS:")
        for archivo in ok:
            print(f"   - {archivo}")
        print()
    
    total = len(hashes_v1_0_0)
    correctos = len(ok)
    
    print("=" * 80)
    print(f"RESULTADO: {correctos}/{total} archivos verificados correctamente")
    
    if correctos == total:
        print("✓ TODOS LOS ARCHIVOS COINCIDEN CON LA VERSIÓN 1.0.0")
    else:
        print("⚠️  ALGUNOS ARCHIVOS HAN SIDO MODIFICADOS O ESTÁN FALTANTES")
    
    print("=" * 80)


def menu_principal():
    """
    Muestra el menú principal del script.
    """
    while True:
        print("\n" + "=" * 80)
        print(" " * 25 + "MyChat - Utilidad de Versiones")
        print("=" * 80)
        print()
        print("1. Generar reporte de MD5 de archivos actuales")
        print("2. Verificar integridad contra versión 1.0.0")
        print("3. Salir")
        print()
        
        opcion = input("Selecciona una opción (1-3): ").strip()
        
        if opcion == "1":
            print()
            generar_reporte_md5()
        elif opcion == "2":
            print()
            verificar_version_1_0_0()
        elif opcion == "3":
            print("\nSaliendo...")
            break
        else:
            print("\n❌ Opción no válida. Por favor, selecciona 1, 2 o 3.")
        
        input("\nPresiona Enter para continuar...")


if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print("\n\nInterrumpido por el usuario. Saliendo...")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        import traceback
        traceback.print_exc()
