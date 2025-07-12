// app/api/foods/goal/route.js
import { NextResponse } from 'next/server';
import { query } from '@/lib/db';
import { Security } from '@/lib/security';

export async function POST(request) {
  try {
    const user = await Security.authenticateRequest(request);
    const body = await request.json();
    const { daily_goal } = body;

    if (!daily_goal || daily_goal <= 0) {
      return NextResponse.json(
        { error: 'La meta diaria debe ser un número positivo' },
        { status: 400 }
      );
    }

    const goalInt = parseInt(daily_goal);

    if (isNaN(goalInt) || goalInt <= 0 || goalInt > 10000) {
      return NextResponse.json(
        { error: 'La meta diaria debe ser entre 1 y 10000 calorías' },
        { status: 400 }
      );
    }

    await query(`
      UPDATE users 
      SET daily_calorie_goal = ?, updated_at = NOW() 
      WHERE id = ?
    `, [goalInt, user.id]);

    await Security.logSecurityEvent(user.id, 'DAILY_GOAL_UPDATED', request, {
      old_goal: user.daily_calorie_goal,
      new_goal: goalInt
    });

    return NextResponse.json({
      success: true,
      daily_goal: goalInt,
      message: 'Meta diaria actualizada exitosamente'
    });

  } catch (error) {
    console.error('Goal POST error:', error);
    return NextResponse.json(
      { error: error.message || 'Error al actualizar meta diaria' },
      { status: error.message.includes('Token') || error.message.includes('Sesión') ? 401 : 500 }
    );
  }
}