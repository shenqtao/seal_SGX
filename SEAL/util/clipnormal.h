#pragma once

#include <random>
#include <cmath>
#include <algorithm>
#include <limits>

using std::numeric_limits;

template<class _Real,
	size_t _Bits,
	class _Gen>
	_Real generate_canonical(_Gen& _Gx)
{	// build a floating-point value from random sequence
	//static_assert(_Is_RealType<_Real>::value,
	//	"invalid template argument for generate_canonical");

	const size_t _Digits = static_cast<size_t>(numeric_limits<_Real>::digits);
	const size_t _Minbits = _Digits < _Bits ? _Digits : _Bits;

	const _Real _Gxmin = static_cast<_Real>((_Gx.min)());
	const _Real _Gxmax = static_cast<_Real>((_Gx.max)());
	const _Real _Rx = (_Gxmax - _Gxmin) + static_cast<_Real>(1);

	const int _Ceil = static_cast<int>(std::ceil(
		static_cast<_Real>(_Minbits) / log2(_Rx)));
	const int _Kx = _Ceil < 1 ? 1 : _Ceil;

	_Real _Ans = static_cast<_Real>(0);
	_Real _Factor = static_cast<_Real>(1);

	for (int _Idx = 0; _Idx < _Kx; ++_Idx)
	{	// add in another set of bits
		_Ans += (static_cast<_Real>(_Gx()) - _Gxmin) * _Factor;
		_Factor *= _Rx;
	}

	return (_Ans / _Factor);
}

#define _NRAND(eng, resty) \
	( generate_canonical<resty, static_cast<size_t>(-1)>(eng))

template<class _Ty = double>
class normal_distribution
{	// template class for normal distribution
public:
	//static_assert(_Is_RealType<_Ty>::value,
	//	"invalid template argument for normal_distribution");

	typedef normal_distribution<_Ty> _Myt;
	typedef _Ty result_type;

	struct param_type
	{	// parameter package
		typedef _Myt distribution_type;

		explicit param_type(_Ty _Mean0 = 0.0, _Ty _Sigma0 = 1.0)
		{	// construct from parameters
			_Init(_Mean0, _Sigma0);
		}

		bool operator==(const param_type& _Right) const
		{	// test for equality
			return (_Mean == _Right._Mean && _Sigma == _Right._Sigma);
		}

		bool operator!=(const param_type& _Right) const
		{	// test for inequality
			return (!(*this == _Right));
		}

		_Ty mean() const
		{	// return mean value
			return (_Mean);
		}

		_Ty sigma() const
		{	// return sigma value
			return (_Sigma);
		}

		_Ty stddev() const
		{	// return sigma value
			return (_Sigma);
		}

		void _Init(_Ty _Mean0, _Ty _Sigma0)
		{	// set internal state
			//_RNG_ASSERT(0.0 < _Sigma0,
			//	"invalid sigma argument for normal_distribution");
			_Mean = _Mean0;
			_Sigma = _Sigma0;
		}

		_Ty _Mean;
		_Ty _Sigma;
	};

	explicit normal_distribution(_Ty _Mean0 = 0.0, _Ty _Sigma0 = 1.0)
		: _Par(_Mean0, _Sigma0), _Valid(false), _X2(0)
	{	// construct
	}

	explicit normal_distribution(const param_type& _Par0)
		: _Par(_Par0), _Valid(false), _X2(0)
	{	// construct from parameter package
	}

	_Ty mean() const
	{	// return mean value
		return (_Par.mean());
	}

	_Ty sigma() const
	{	// return sigma value
		return (_Par.sigma());
	}

	_Ty stddev() const
	{	// return sigma value
		return (_Par.sigma());
	}

	param_type param() const
	{	// return parameter package
		return (_Par);
	}

	void param(const param_type& _Par0)
	{	// set parameter package
		_Par = _Par0;
		reset();
	}

	result_type(min)() const
	{	// get smallest possible result
		return (numeric_limits<result_type>::denorm_min());
	}

	result_type(max)() const
	{	// get largest possible result
		return ((numeric_limits<result_type>::max)());
	}

	void reset()
	{	// clear internal state
		_Valid = false;
	}

	template<class _Engine>
	result_type operator()(_Engine& _Eng)
	{	// return next value
		return (_Eval(_Eng, _Par));
	}

	template<class _Engine>
	result_type operator()(_Engine& _Eng, const param_type& _Par0)
	{	// return next value, given parameter package
		reset();
		return (_Eval(_Eng, _Par0, false));
	}


private:
	template<class _Engine>
	result_type _Eval(_Engine& _Eng, const param_type& _Par0,
		bool _Keep = true)
	{	// compute next value
		// Knuth, vol. 2, p. 122, alg. P
		_Ty _Res;
		if (_Keep && _Valid)
		{	// return stored value
			_Res = _X2;
			_Valid = false;
		}
		else
		{	// generate two values, store one, return one
			double _V1, _V2, _Sx;
			for (; ; )
			{	// reject bad values///////////////////////////////////////////////////////////////////changed by yichen

				_V1 = 2 * _NRAND(_Eng, _Ty) - 1.0;
				_V2 = 2 * _NRAND(_Eng, _Ty) - 1.0;
				_Sx = _V1 * _V1 + _V2 * _V2;
				//_V1 = 0.34700068881909840;
				//_V2 = 0.88990814494692461;
				//_Sx = 0.91234598448380533;
				if (_Sx < 1.0)
					break;
			}
			double _Fx = std::sqrt(-2.0 * std::log(_Sx) / _Sx);
			if (_Keep)
			{	// save second value for next call
				_X2 = _Fx * _V2;
				_Valid = true;
			}
			_Res = _Fx * _V1;
		}
		return (_Res * _Par0._Sigma + _Par0._Mean);
	}

	param_type _Par;
	bool _Valid;
	_Ty _X2;
};

namespace seal
{
    namespace util
    {
        class ClippedNormalDistribution
        {
        public:
            typedef double result_type;

            typedef ClippedNormalDistribution param_type;

            ClippedNormalDistribution(result_type mean, result_type standard_deviation, result_type max_deviation);

            template <typename RNG>
            result_type operator()(RNG &engine, const param_type &parm)
            {
                param(parm);
                return operator()(engine);
            }

            template <typename RNG>
            result_type operator()(RNG &engine)
            {
                result_type mean = normal_.mean();
                while (true)
                {
                    result_type value = normal_(engine);
					result_type deviation;
					if (value - mean >= 0)
						deviation = value - mean;
					else
						deviation = 0 - (value - mean);
                    //result_type deviation = abs(value - mean);
                    if (deviation <= max_deviation_)
                    {
                        return value;
                    }
                }
            }

            result_type mean() const
            {
                return normal_.mean();
            }

            result_type standard_deviation() const
            {
                return normal_.stddev();
            }

            result_type max_deviation() const
            {
                return max_deviation_;
            }

            result_type min() const
            {
                return normal_.mean() - max_deviation_;
            }

            result_type max() const
            {
                return normal_.mean() + max_deviation_;
            }

            param_type param() const
            {
                return *this;
            }

            void param(const param_type &parm)
            {
                *this = parm;
            }

            void reset()
            {
                normal_.reset();
            }

        private:
            normal_distribution<result_type> normal_;

            result_type max_deviation_;
        };
    }
}
