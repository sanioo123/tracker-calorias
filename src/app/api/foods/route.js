// app/api/foods/route.js
import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { Security } from '@/lib/security';

export async function GET(request) {
  try {
    const user = await Security.authenticateRequest(request);
    const today = new Date().toISOString().split('T')[0];
    
    const foods = await query(`
      SELECT id, name, calories, consumed_at,
             TIME_FORMAT(consumed_at, '%H:%i') as time
      FROM foods 
      WHERE user_id = ? AND date_consumed = ?
      ORDER BY consumed_at DESC
    `, [user.id, today]);

    return NextResponse.json({
      success: true,
      foods: foods
    });

  } catch (error) {
    console.error('Foods GET error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al obtener alimentos' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}

export async function POST(request) {
  try {
    const user = await Security.authenticateRequest(request);
    const body = await request.json();
    const { name, calories } = body;

    if (!name || !name.trim()) {
      return NextResponse.json(
        { error: 'El nombre del alimento es requerido' },
        { status: 400 }
      );
    }

    if (!calories || calories <= 0) {
      return NextResponse.json(
        { error: 'Las calorías deben ser un número positivo' },
        { status: 400 }
      );
    }

    const sanitizedName = Security.sanitizeInput(name.trim());
    const caloriesInt = parseInt(calories);

    if (isNaN(caloriesInt) || caloriesInt <= 0) {
      return NextResponse.json(
        { error: 'Las calorías deben ser un número válido' },
        { status: 400 }
      );
    }

    if (!Security.checkRateLimit(`add_food_${user.id}`, 10, 60000)) { // 10 por minuto
      return NextResponse.json(
        { error: 'Demasiados alimentos agregados. Espera un momento' },
        { status: 429 }
      );
    }

    const now = new Date();
    const today = now.toISOString().split('T')[0];
    
    const result = await query(`
      INSERT INTO foods (user_id, name, calories, consumed_at, date_consumed) 
      VALUES (?, ?, ?, ?, ?)
    `, [user.id, sanitizedName, caloriesInt, now, today]);

    const newFood = {
      id: result.insertId,
      name: sanitizedName,
      calories: caloriesInt,
      consumed_at: now.toISOString(),
      time: now.toTimeString().slice(0, 5)
    };

    await Security.logSecurityEvent(user.id, 'FOOD_ADDED', request, {
      food_name: sanitizedName,
      calories: caloriesInt
    });

    return NextResponse.json({
      success: true,
      food: newFood,
      message: 'Alimento agregado exitosamente'
    });

  } catch (error) {
    console.error('Foods POST error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al agregar alimento' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}

export async function DELETE(request) {
  try {
    const user = await Security.authenticateRequest(request);
    
    const { searchParams } = new URL(request.url);
    const foodId = searchParams.get('id');

    if (!foodId) {
      return NextResponse.json(
        { error: 'ID del alimento requerido' },
        { status: 400 }
      );
    }

    const foods = await query(`
      SELECT id, name, calories FROM foods 
      WHERE id = ? AND user_id = ?
    `, [foodId, user.id]);

    if (foods.length === 0) {
      return NextResponse.json(
        { error: 'Alimento no encontrado o no autorizado' },
        { status: 404 }
      );
    }

    await query(`
      DELETE FROM foods 
      WHERE id = ? AND user_id = ?
    `, [foodId, user.id]);

    await Security.logSecurityEvent(user.id, 'FOOD_DELETED', request, {
      food_id: foodId,
      food_name: foods[0].name,
      calories: foods[0].calories
    });

    return NextResponse.json({
      success: true,
      message: 'Alimento eliminado exitosamente'
    });

  } catch (error) {
    console.error('Foods DELETE error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al eliminar alimento' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}